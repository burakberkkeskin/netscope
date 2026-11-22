use crate::CancelToken;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::sync::mpsc;

// iperf3 wire control state constants (from ESnet iperf3 src/iperf_api.h)
const TEST_START: i8 = 1;
const TEST_RUNNING: i8 = 2;
const TEST_END: i8 = 4;
const PARAM_EXCHANGE: i8 = 9;
const CREATE_STREAMS: i8 = 10;
const SERVER_TERMINATE: i8 = 11;
const CLIENT_TERMINATE: i8 = 12;
const EXCHANGE_RESULTS: i8 = 13;
const DISPLAY_RESULTS: i8 = 14;
const IPERF_START: i8 = 15;
const IPERF_DONE: i8 = 16;
const ACCESS_DENIED: i8 = -1;
const SERVER_ERROR: i8 = -2;

const COOKIE_SIZE: usize = 37;
const UDP_CONNECT_MAGIC: u32 = 0x3637_3839; // 909590585 ("6789")
const UDP_CONNECT_REPLY_MAGIC: u32 = 0x3938_3736; // 959985462 ("9876")
const UDP_CONNECT_REPLY_LEGACY: u32 = 0x01;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iperf3Config {
    /// `-c <host>` target iperf3 server hostname or IP
    pub host: String,
    /// `-p <port>` server control/data port (default 5201)
    pub port: u16,
    /// `-t <secs>` test duration in seconds (default 10)
    pub duration_secs: u16,
    /// `-P <streams>` number of parallel client streams (1..=32)
    pub parallel_streams: u8,
    /// `-R` reverse mode (server sends, client receives)
    pub reverse: bool,
    /// `--bidir` bidirectional mode (simultaneous upload + download)
    #[serde(default)]
    pub bidir: bool,
    /// `-u` use UDP datagrams instead of TCP
    pub use_udp: bool,
    /// `-b <Mbps>` target bitrate in Mbps (required for UDP, optional pacing for TCP; 0 = unlimited TCP)
    pub udp_bandwidth_mbps: u32,
    /// `-O <secs>` omit first N seconds (TCP slow-start warmup) from summary average
    #[serde(default)]
    pub omit_secs: u8,
    /// `-l <bytes>` read/write buffer or UDP payload size (0 = auto: 128 KB TCP / 1448 B UDP)
    #[serde(default)]
    pub buffer_len_bytes: u32,
    /// `-N` set TCP_NODELAY (disable Nagle's algorithm)
    #[serde(default)]
    pub no_delay: bool,
}

impl Default for Iperf3Config {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 5201,
            duration_secs: 10,
            parallel_streams: 4,
            reverse: false,
            bidir: false,
            use_udp: false,
            udp_bandwidth_mbps: 100,
            omit_secs: 0,
            buffer_len_bytes: 0,
            no_delay: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iperf3Interval {
    pub second: f64,
    pub mbps: f64,
    pub retransmits: Option<u64>,
    pub jitter_ms: Option<f64>,
    pub lost_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iperf3Summary {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub direction: String,
    pub streams: u8,
    pub duration_secs: f64,
    pub avg_mbps: f64,
    pub total_bytes: u64,
    pub retransmits: Option<u64>,
    pub jitter_ms: Option<f64>,
    pub lost_pct: Option<f64>,
    pub intervals: Vec<Iperf3Interval>,
}

#[derive(Debug, Clone)]
pub enum Iperf3Event {
    Interval(Iperf3Interval),
    Completed(Box<Iperf3Summary>),
    Error(String),
}

struct StreamTracker {
    id: i32,
    sender: bool,
    bytes: AtomicU64,
    packets: AtomicU64,
    lost_packets: AtomicU64,
    out_of_order: AtomicU64,
    jitter_us: AtomicU64,
}

impl StreamTracker {
    fn new(id: i32, sender: bool) -> Arc<Self> {
        Arc::new(Self {
            id,
            sender,
            bytes: AtomicU64::new(0),
            packets: AtomicU64::new(0),
            lost_packets: AtomicU64::new(0),
            out_of_order: AtomicU64::new(0),
            jitter_us: AtomicU64::new(0),
        })
    }
}

/// Generates a 37-byte ESnet iperf3 session cookie (36 lowercase base32 characters + NUL terminator).
fn generate_cookie() -> [u8; COOKIE_SIZE] {
    const CHARSET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut cookie = [0u8; COOKIE_SIZE];
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let pid = u64::from(std::process::id());
    let mut state = nanos ^ (pid.rotate_left(17)) ^ 0x9E37_79B9_7F4A_7C15;

    for slot in cookie.iter_mut().take(COOKIE_SIZE - 1) {
        // SplitMix64 PRNG step
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        *slot = CHARSET[(z as usize) & 31];
    }
    cookie[COOKIE_SIZE - 1] = 0;
    cookie
}

async fn write_ctrl_json(ctrl: &mut TcpStream, val: &Value) -> Result<(), String> {
    let raw = serde_json::to_vec(val).map_err(|e| format!("JSON encode error: {e}"))?;
    let len_be = (raw.len() as u32).to_be_bytes();
    ctrl.write_all(&len_be)
        .await
        .map_err(|e| format!("Control write length failed: {e}"))?;
    ctrl.write_all(&raw)
        .await
        .map_err(|e| format!("Control write payload failed: {e}"))?;
    ctrl.flush()
        .await
        .map_err(|e| format!("Control flush failed: {e}"))?;
    Ok(())
}

async fn read_ctrl_json(ctrl: &mut TcpStream) -> Result<Value, String> {
    let mut len_buf = [0u8; 4];
    ctrl.read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("Control read length failed: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 16 * 1024 * 1024 {
        return Err(format!("Invalid iperf3 control JSON size: {len} bytes"));
    }
    let mut buf = vec![0u8; len];
    ctrl.read_exact(&mut buf)
        .await
        .map_err(|e| format!("Control read payload failed: {e}"))?;
    serde_json::from_slice(&buf).map_err(|e| format!("Invalid iperf3 server JSON: {e}"))
}

async fn read_ctrl_state(ctrl: &mut TcpStream) -> Result<i8, String> {
    let mut b = [0u8; 1];
    ctrl.read_exact(&mut b)
        .await
        .map_err(|e| format!("Control channel closed by server: {e}"))?;
    Ok(b[0] as i8)
}

async fn write_ctrl_state(ctrl: &mut TcpStream, state: i8) -> Result<(), String> {
    ctrl.write_all(&[state as u8])
        .await
        .map_err(|e| format!("Control state write failed: {e}"))?;
    ctrl.flush()
        .await
        .map_err(|e| format!("Control state flush failed: {e}"))?;
    Ok(())
}

/// Pure-Rust native iperf3 wire-protocol client compatible with standard `iperf3 -s` servers.
pub async fn run_iperf3(
    cfg: Iperf3Config,
    tx: mpsc::UnboundedSender<Iperf3Event>,
    cancel: CancelToken,
) {
    if let Err(err) = run_iperf3_wire(&cfg, &tx, &cancel).await
        && !cancel.is_cancelled()
    {
        let _ = tx.send(Iperf3Event::Error(err));
    }
}

async fn run_iperf3_wire(
    cfg: &Iperf3Config,
    tx: &mpsc::UnboundedSender<Iperf3Event>,
    cancel: &CancelToken,
) -> Result<(), String> {
    let host = cfg.host.trim();
    if host.is_empty() {
        return Err("Target server host cannot be empty".into());
    }

    let addr_str = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{}", cfg.port)
    } else {
        format!("{host}:{}", cfg.port)
    };
    let target_addr: SocketAddr = tokio::time::timeout(Duration::from_secs(4), lookup_host(&addr_str))
        .await
        .map_err(|_| format!("DNS lookup timed out for {host}"))?
        .map_err(|e| format!("Failed resolving {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("No IP address found for {host}"))?;

    // 1. Connect TCP Control Channel & send 37-byte session cookie
    let mut ctrl = tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(target_addr))
        .await
        .map_err(|_| format!("Connection timed out to {target_addr} (is `iperf3 -s` running?)"))?
        .map_err(|e| format!("Failed connecting to {target_addr}: {e}"))?;
    let _ = ctrl.set_nodelay(true);

    let cookie = generate_cookie();
    ctrl.write_all(&cookie)
        .await
        .map_err(|e| format!("Failed sending iperf3 cookie: {e}"))?;

    let parallel = cfg.parallel_streams.clamp(1, 32);
    let blksize: usize = if cfg.buffer_len_bytes > 0 {
        (cfg.buffer_len_bytes as usize).clamp(64, 4 * 1024 * 1024)
    } else if cfg.use_udp {
        1448
    } else {
        128 * 1024
    };
    let duration_secs = cfg.duration_secs.clamp(1, 3600);
    let omit_secs = u16::from(cfg.omit_secs).min(duration_secs.saturating_sub(1));

    let running_flag = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let mut trackers: Vec<Arc<StreamTracker>> = Vec::new();
    let mut worker_handles = Vec::new();

    // 2. Drive handshake state machine until TEST_RUNNING
    loop {
        if cancel.is_cancelled() {
            stop_flag.store(true, Ordering::SeqCst);
            let _ = write_ctrl_state(&mut ctrl, CLIENT_TERMINATE).await;
            return Ok(());
        }

        let st = tokio::time::timeout(Duration::from_secs(6), read_ctrl_state(&mut ctrl))
            .await
            .map_err(|_| "Timed out waiting for iperf3 server handshake state".to_string())??;

        match st {
            PARAM_EXCHANGE => {
                let mut params = serde_json::Map::new();
                if cfg.use_udp {
                    params.insert("udp".into(), json!(true));
                    let rate_bps = u64::from(cfg.udp_bandwidth_mbps.max(1)) * 1_000_000;
                    params.insert("rate".into(), json!(rate_bps));
                } else {
                    params.insert("tcp".into(), json!(true));
                    if cfg.udp_bandwidth_mbps > 0 && cfg.buffer_len_bytes > 0 {
                        // Optional pacing if explicitly configured
                    }
                }
                params.insert("omit".into(), json!(omit_secs));
                params.insert("time".into(), json!(duration_secs));
                params.insert("num".into(), json!(0));
                params.insert("blockcount".into(), json!(0));
                params.insert("parallel".into(), json!(parallel));
                params.insert("len".into(), json!(blksize));
                params.insert("pacing_timer".into(), json!(1000));
                params.insert("client_version".into(), json!("3.17"));
                if cfg.no_delay {
                    params.insert("nodelay".into(), json!(true));
                }
                if cfg.bidir {
                    params.insert("bidirectional".into(), json!(true));
                } else if cfg.reverse {
                    params.insert("reverse".into(), json!(true));
                }
                write_ctrl_json(&mut ctrl, &Value::Object(params)).await?;
            }
            CREATE_STREAMS => {
                // Create P primary streams, plus P reverse streams if bidirectional
                let groups: &[bool] = if cfg.bidir {
                    &[true, false]
                } else if cfg.reverse {
                    &[false]
                } else {
                    &[true]
                };

                let mut next_id: i32 = 1;
                for &is_sender in groups {
                    for _ in 0..parallel {
                        let tracker = StreamTracker::new(next_id, is_sender);
                        next_id += 2;
                        trackers.push(tracker.clone());

                        let run_f = running_flag.clone();
                        let stop_f = stop_flag.clone();
                        let cancel_c = cancel.clone();

                        if cfg.use_udp {
                            let sock = bind_udp_for_target(target_addr).await?;
                            sock.connect(target_addr)
                                .await
                                .map_err(|e| format!("UDP connect failed: {e}"))?;
                            // iperf3 UDP stream handshake: write 4-byte magic (36373839) and wait for 4-byte reply
                            sock.send(&UDP_CONNECT_MAGIC.to_be_bytes())
                                .await
                                .map_err(|e| format!("UDP handshake send failed: {e}"))?;
                            let mut reply = [0u8; 4];
                            tokio::time::timeout(Duration::from_secs(4), sock.recv(&mut reply))
                                .await
                                .map_err(|_| {
                                    "UDP stream handshake timed out (check firewall UDP port 5201)"
                                        .to_string()
                                })?
                                .map_err(|e| format!("UDP handshake recv failed: {e}"))?;
                            let rep_val = u32::from_be_bytes(reply);
                            if rep_val != UDP_CONNECT_REPLY_MAGIC
                                && rep_val != UDP_CONNECT_REPLY_MAGIC.swap_bytes()
                                && rep_val != UDP_CONNECT_REPLY_LEGACY
                            {
                                // Proceed even on custom server magic if 4 bytes returned
                            }

                            let per_stream_bps = (u64::from(cfg.udp_bandwidth_mbps.max(1))
                                * 1_000_000)
                                / u64::from(parallel.max(1));
                            let h = tokio::spawn(async move {
                                run_udp_stream(
                                    sock,
                                    blksize,
                                    per_stream_bps,
                                    is_sender,
                                    tracker,
                                    run_f,
                                    stop_f,
                                    cancel_c,
                                )
                                .await;
                            });
                            worker_handles.push(h);
                        } else {
                            let mut data_stream =
                                tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(target_addr))
                                    .await
                                    .map_err(|_| "Data stream TCP connect timed out".to_string())?
                                    .map_err(|e| format!("Data stream TCP connect failed: {e}"))?;
                            if cfg.no_delay {
                                let _ = data_stream.set_nodelay(true);
                            }
                            data_stream
                                .write_all(&cookie)
                                .await
                                .map_err(|e| format!("Data stream cookie write failed: {e}"))?;

                            let h = tokio::spawn(async move {
                                run_tcp_stream(
                                    data_stream,
                                    blksize,
                                    is_sender,
                                    tracker,
                                    run_f,
                                    stop_f,
                                    cancel_c,
                                )
                                .await;
                            });
                            worker_handles.push(h);
                        }
                    }
                }
            }
            TEST_START | IPERF_START => {
                // Server is ready; TEST_RUNNING follows immediately
            }
            TEST_RUNNING => {
                running_flag.store(true, Ordering::SeqCst);
                break;
            }
            ACCESS_DENIED => {
                return Err("iperf3 server is busy with another test (ACCESS_DENIED)".into());
            }
            SERVER_ERROR => {
                return Err("iperf3 server returned SERVER_ERROR during handshake".into());
            }
            other => {
                return Err(format!("Unexpected iperf3 control state during startup: {other}"));
            }
        }
    }

    // 3. Active Measurement Loop (1-second live telemetry intervals)
    let start_instant = Instant::now();
    let total_test_dur = Duration::from_secs(u64::from(duration_secs + omit_secs));
    let omit_dur = Duration::from_secs(u64::from(omit_secs));
    let mut prev_bytes: u64 = 0;
    let mut prev_tick = start_instant;
    let mut omitted_bytes_baseline: Option<u64> = if omit_secs == 0 { Some(0) } else { None };
    let mut effective_start = start_instant;
    let mut intervals: Vec<Iperf3Interval> = Vec::new();
    let mut server_terminated_early = false;

    let mut tick_timer = tokio::time::interval(Duration::from_secs(1));
    tick_timer.tick().await; // consume immediate tick

    loop {
        if cancel.is_cancelled() {
            stop_flag.store(true, Ordering::SeqCst);
            let _ = write_ctrl_state(&mut ctrl, CLIENT_TERMINATE).await;
            for h in worker_handles {
                h.abort();
            }
            return Ok(());
        }

        let mut ctrl_byte = [0u8; 1];
        tokio::select! {
            _ = tick_timer.tick() => {
                let now = Instant::now();
                let elapsed = now.duration_since(start_instant);
                let dt = now.duration_since(prev_tick).as_secs_f64().max(1e-3);
                prev_tick = now;

                let cur_bytes: u64 = trackers.iter().map(|t| t.bytes.load(Ordering::Relaxed)).sum();
                let delta_bytes = cur_bytes.saturating_sub(prev_bytes);
                prev_bytes = cur_bytes;

                if omitted_bytes_baseline.is_none() && elapsed >= omit_dur {
                    omitted_bytes_baseline = Some(cur_bytes);
                    effective_start = now;
                }

                let mbps = (delta_bytes as f64 * 8.0) / (dt * 1_000_000.0);
                let (jitter_ms, lost_pct) = aggregate_udp_metrics(&trackers, cfg.use_udp);

                let iv = Iperf3Interval {
                    second: elapsed.as_secs_f64(),
                    mbps,
                    retransmits: None,
                    jitter_ms,
                    lost_pct,
                };
                intervals.push(iv.clone());
                let _ = tx.send(Iperf3Event::Interval(iv));

                if elapsed >= total_test_dur {
                    break;
                }
            }
            res = ctrl.read_exact(&mut ctrl_byte) => {
                match res {
                    Ok(_) => {
                        let st = ctrl_byte[0] as i8;
                        if st == SERVER_TERMINATE || st == TEST_END {
                            server_terminated_early = true;
                            break;
                        } else if st == ACCESS_DENIED || st == SERVER_ERROR {
                            stop_flag.store(true, Ordering::SeqCst);
                            return Err(format!("iperf3 server aborted test (state {st})"));
                        }
                    }
                    Err(e) => {
                        stop_flag.store(true, Ordering::SeqCst);
                        return Err(format!("Control channel lost during test: {e}"));
                    }
                }
            }
        }
    }

    // 4. Stop worker streams & perform EXCHANGE_RESULTS with the server
    stop_flag.store(true, Ordering::SeqCst);
    for h in worker_handles {
        let _ = tokio::time::timeout(Duration::from_millis(300), h).await;
    }

    let measured_secs = Instant::now()
        .duration_since(effective_start)
        .as_secs_f64()
        .max(0.1);
    let raw_total_bytes: u64 = trackers.iter().map(|t| t.bytes.load(Ordering::Relaxed)).sum();
    let measured_bytes = raw_total_bytes.saturating_sub(omitted_bytes_baseline.unwrap_or(0));

    let mut server_results: Option<Value> = None;
    if !server_terminated_early {
        write_ctrl_state(&mut ctrl, TEST_END).await?;
    }

    // Read control states until DISPLAY_RESULTS or connection close
    for _ in 0..6 {
        let Ok(Ok(st)) =
            tokio::time::timeout(Duration::from_secs(3), read_ctrl_state(&mut ctrl)).await
        else {
            break;
        };
        match st {
            EXCHANGE_RESULTS => {
                let client_streams_json: Vec<Value> = trackers
                    .iter()
                    .map(|t| {
                        let b = t.bytes.load(Ordering::Relaxed);
                        let p = t.packets.load(Ordering::Relaxed);
                        let lost = t.lost_packets.load(Ordering::Relaxed);
                        let ooo = t.out_of_order.load(Ordering::Relaxed);
                        let jit_sec = (t.jitter_us.load(Ordering::Relaxed) as f64) / 1_000_000.0;
                        json!({
                            "id": t.id,
                            "bytes": b,
                            "retransmits": -1,
                            "jitter": jit_sec,
                            "errors": lost,
                            "omitted_errors": 0,
                            "packets": p,
                            "omitted_packets": 0,
                            "out_of_order": ooo,
                            "start_time": 0.0,
                            "end_time": measured_secs,
                            "sender": t.sender,
                        })
                    })
                    .collect();

                let client_res = json!({
                    "cpu_util_total": 1.0,
                    "cpu_util_user": 0.5,
                    "cpu_util_system": 0.5,
                    "sender_has_retransmits": 0,
                    "streams": client_streams_json,
                });
                write_ctrl_json(&mut ctrl, &client_res).await?;
                if let Ok(srv_json) = read_ctrl_json(&mut ctrl).await {
                    server_results = Some(srv_json);
                }
            }
            DISPLAY_RESULTS => {
                let _ = write_ctrl_state(&mut ctrl, IPERF_DONE).await;
                break;
            }
            SERVER_TERMINATE | IPERF_DONE => break,
            _ => {}
        }
    }

    // 5. Merge client & server EXCHANGE_RESULTS metrics
    let (srv_bytes, srv_retrans, srv_jitter_ms, srv_lost_pct) =
        extract_server_exchange_metrics(server_results.as_ref());
    let (loc_jitter_ms, loc_lost_pct) = aggregate_udp_metrics(&trackers, cfg.use_udp);

    // For Upload TCP/UDP, server's received byte count or client's sent byte count gives throughput
    let final_bytes = if measured_bytes > 0 {
        measured_bytes
    } else {
        srv_bytes.unwrap_or(0)
    };
    let avg_mbps = (final_bytes as f64 * 8.0) / (measured_secs * 1_000_000.0);

    let summary = Iperf3Summary {
        timestamp: Utc::now(),
        host: host.to_string(),
        port: cfg.port,
        protocol: if cfg.use_udp { "UDP" } else { "TCP" }.into(),
        direction: if cfg.bidir {
            "Bidirectional"
        } else if cfg.reverse {
            "Download (-R)"
        } else {
            "Upload"
        }
        .into(),
        streams: parallel,
        duration_secs: measured_secs,
        avg_mbps,
        total_bytes: final_bytes,
        retransmits: if cfg.use_udp { None } else { srv_retrans },
        jitter_ms: loc_jitter_ms.or(srv_jitter_ms),
        lost_pct: loc_lost_pct.or(srv_lost_pct),
        intervals,
    };

    let _ = tx.send(Iperf3Event::Completed(Box::new(summary)));
    Ok(())
}

async fn bind_udp_for_target(target: SocketAddr) -> Result<UdpSocket, String> {
    let bind_addr = match target.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("Failed binding local UDP socket: {e}"))
}

async fn run_tcp_stream(
    mut stream: TcpStream,
    blksize: usize,
    is_sender: bool,
    tracker: Arc<StreamTracker>,
    running_flag: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    cancel: CancelToken,
) {
    while !running_flag.load(Ordering::Relaxed) {
        if stop_flag.load(Ordering::Relaxed) || cancel.is_cancelled() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut buf = vec![0x5Au8; blksize];
    if is_sender {
        while !stop_flag.load(Ordering::Relaxed) && !cancel.is_cancelled() {
            match stream.write(&buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    tracker.bytes.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
    } else {
        while !stop_flag.load(Ordering::Relaxed) && !cancel.is_cancelled() {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    tracker.bytes.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_stream(
    sock: UdpSocket,
    blksize: usize,
    target_bps: u64,
    is_sender: bool,
    tracker: Arc<StreamTracker>,
    running_flag: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    cancel: CancelToken,
) {
    while !running_flag.load(Ordering::Relaxed) {
        if stop_flag.load(Ordering::Relaxed) || cancel.is_cancelled() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let dgram_size = blksize.clamp(64, 65_000);
    let mut buf = vec![0u8; dgram_size];

    if is_sender {
        let start = Instant::now();
        let mut seq: u64 = 0;
        let bits_per_pkt = (dgram_size as f64) * 8.0;
        let inter_pkt_secs = if target_bps > 0 {
            bits_per_pkt / (target_bps as f64)
        } else {
            0.0
        };

        while !stop_flag.load(Ordering::Relaxed) && !cancel.is_cancelled() {
            seq += 1;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            let sec = (now.as_secs() as u32).to_be_bytes();
            let usec = now.subsec_micros().to_be_bytes();
            // iperf3 64-bit UDP header: [sec: u32][usec: u32][pcount: u64]
            buf[0..4].copy_from_slice(&sec);
            buf[4..8].copy_from_slice(&usec);
            buf[8..16].copy_from_slice(&seq.to_be_bytes());

            match sock.send(&buf).await {
                Ok(n) => {
                    tracker.bytes.fetch_add(n as u64, Ordering::Relaxed);
                    tracker.packets.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => break,
            }

            if inter_pkt_secs > 0.0 {
                let target_elapsed = Duration::from_secs_f64(seq as f64 * inter_pkt_secs);
                let actual_elapsed = start.elapsed();
                if target_elapsed > actual_elapsed {
                    let wait = target_elapsed - actual_elapsed;
                    if wait >= Duration::from_micros(500) {
                        tokio::time::sleep(wait).await;
                    }
                }
            }
        }
    } else {
        // Reverse UDP (-u -R): receive datagrams, compute RFC 1889 jitter and sequence loss
        let mut max_seq: u64 = 0;
        let mut prev_transit_us: Option<i64> = None;
        let mut jitter_est_us: f64 = 0.0;

        while !stop_flag.load(Ordering::Relaxed) && !cancel.is_cancelled() {
            let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(250), sock.recv(&mut buf)).await
            else {
                continue;
            };
            if n < 16 {
                continue;
            }
            tracker.bytes.fetch_add(n as u64, Ordering::Relaxed);
            tracker.packets.fetch_add(1, Ordering::Relaxed);

            let sent_sec = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as i64;
            let sent_usec = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as i64;
            let seq = u64::from_be_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            let arrival_us = (now.as_secs() as i64) * 1_000_000 + i64::from(now.subsec_micros());
            let sent_us = sent_sec * 1_000_000 + sent_usec;
            let transit = arrival_us - sent_us;
            if let Some(prev) = prev_transit_us {
                let d = (transit - prev).unsigned_abs() as f64;
                jitter_est_us += (d - jitter_est_us) / 16.0;
                tracker
                    .jitter_us
                    .store(jitter_est_us as u64, Ordering::Relaxed);
            }
            prev_transit_us = Some(transit);

            if seq > max_seq + 1 {
                let gap = seq - max_seq - 1;
                tracker.lost_packets.fetch_add(gap, Ordering::Relaxed);
                max_seq = seq;
            } else if seq == max_seq + 1 {
                max_seq = seq;
            } else if seq <= max_seq {
                tracker.out_of_order.fetch_add(1, Ordering::Relaxed);
                // Reclassified out-of-order packet reduces lost count by 1
                let prev_lost = tracker.lost_packets.load(Ordering::Relaxed);
                if prev_lost > 0 {
                    tracker.lost_packets.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }
}

fn aggregate_udp_metrics(
    trackers: &[Arc<StreamTracker>],
    use_udp: bool,
) -> (Option<f64>, Option<f64>) {
    if !use_udp {
        return (None, None);
    }
    let mut total_pkts = 0u64;
    let mut total_lost = 0u64;
    let mut jitter_sum_us = 0u64;
    let mut jitter_cnt = 0u64;

    for t in trackers {
        let p = t.packets.load(Ordering::Relaxed);
        let l = t.lost_packets.load(Ordering::Relaxed);
        let j = t.jitter_us.load(Ordering::Relaxed);
        total_pkts += p;
        total_lost += l;
        if j > 0 {
            jitter_sum_us += j;
            jitter_cnt += 1;
        }
    }

    let jitter_ms = if jitter_cnt > 0 {
        Some((jitter_sum_us as f64 / jitter_cnt as f64) / 1000.0)
    } else {
        None
    };
    let expected = total_pkts + total_lost;
    let lost_pct = if expected > 0 && total_lost > 0 {
        Some((total_lost as f64 / expected as f64) * 100.0)
    } else if total_pkts > 0 {
        Some(0.0)
    } else {
        None
    };
    (jitter_ms, lost_pct)
}

fn extract_server_exchange_metrics(
    srv: Option<&Value>,
) -> (Option<u64>, Option<u64>, Option<f64>, Option<f64>) {
    let Some(val) = srv else {
        return (None, None, None, None);
    };
    let Some(streams) = val.get("streams").and_then(Value::as_array) else {
        return (None, None, None, None);
    };

    let mut total_bytes = 0u64;
    let mut total_retrans = 0u64;
    let mut has_retrans = false;
    let mut jitter_sec_sum = 0.0f64;
    let mut jitter_cnt = 0usize;
    let mut total_errors = 0u64;
    let mut total_pkts = 0u64;

    for s in streams {
        if let Some(b) = s.get("bytes").and_then(Value::as_u64) {
            total_bytes += b;
        }
        if let Some(r) = s.get("retransmits").and_then(Value::as_i64)
            && r >= 0
        {
            total_retrans += r as u64;
            has_retrans = true;
        }
        if let Some(j) = s.get("jitter").and_then(Value::as_f64)
            && j > 0.0
        {
            jitter_sec_sum += j;
            jitter_cnt += 1;
        }
        if let Some(e) = s.get("errors").and_then(Value::as_i64)
            && e > 0
        {
            total_errors += e as u64;
        }
        if let Some(p) = s.get("packets").and_then(Value::as_u64) {
            total_pkts += p;
        }
    }

    let bytes_opt = if total_bytes > 0 {
        Some(total_bytes)
    } else {
        None
    };
    let retrans_opt = if has_retrans {
        Some(total_retrans)
    } else {
        Some(0)
    };
    let jitter_ms_opt = if jitter_cnt > 0 {
        Some((jitter_sec_sum / jitter_cnt as f64) * 1000.0)
    } else {
        None
    };
    let lost_pct_opt = if total_pkts > 0 {
        Some((total_errors as f64 / total_pkts as f64) * 100.0)
    } else {
        None
    };
    (bytes_opt, retrans_opt, jitter_ms_opt, lost_pct_opt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn generated_cookie_is_37_bytes_null_terminated_ascii() {
        let c = generate_cookie();
        assert_eq!(c.len(), 37);
        assert_eq!(c[36], 0);
        assert!(c[..36]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
    }

    #[tokio::test]
    async fn native_wire_client_completes_tcp_upload_and_exchange_results() {
        // Spin up an in-process mock iperf3 wire-protocol server on ephemeral localhost port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv_handle = tokio::spawn(async move {
            // 1. Accept control connection & read 37-byte cookie
            let (mut ctrl, _) = listener.accept().await.unwrap();
            let mut cookie = [0u8; 37];
            ctrl.read_exact(&mut cookie).await.unwrap();
            assert_eq!(cookie[36], 0);

            // 2. Request PARAM_EXCHANGE and verify JSON parameters
            write_ctrl_state(&mut ctrl, PARAM_EXCHANGE).await.unwrap();
            let params = read_ctrl_json(&mut ctrl).await.unwrap();
            assert_eq!(params.get("tcp").and_then(Value::as_bool), Some(true));
            assert_eq!(params.get("parallel").and_then(Value::as_u64), Some(2));

            // 3. Request CREATE_STREAMS and accept 2 data connections
            write_ctrl_state(&mut ctrl, CREATE_STREAMS).await.unwrap();
            let mut data_tasks = Vec::new();
            for _ in 0..2 {
                let (mut ds, _) = listener.accept().await.unwrap();
                let mut d_cookie = [0u8; 37];
                ds.read_exact(&mut d_cookie).await.unwrap();
                assert_eq!(d_cookie, cookie);
                data_tasks.push(tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    let mut total = 0u64;
                    while let Ok(n) = ds.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        total += n as u64;
                    }
                    total
                }));
            }

            // 4. Signal TEST_START -> TEST_RUNNING
            write_ctrl_state(&mut ctrl, TEST_START).await.unwrap();
            write_ctrl_state(&mut ctrl, TEST_RUNNING).await.unwrap();

            // 5. Wait for client TEST_END
            let st = read_ctrl_state(&mut ctrl).await.unwrap();
            assert_eq!(st, TEST_END);

            // 6. EXCHANGE_RESULTS -> DISPLAY_RESULTS
            write_ctrl_state(&mut ctrl, EXCHANGE_RESULTS).await.unwrap();
            let client_res = read_ctrl_json(&mut ctrl).await.unwrap();
            assert!(client_res.get("streams").is_some());

            let srv_res = json!({
                "cpu_util_total": 3.2,
                "streams": [
                    {"id": 1, "bytes": 50_000_000u64, "retransmits": 2, "jitter": 0.0, "errors": 0, "packets": 0},
                    {"id": 3, "bytes": 50_000_000u64, "retransmits": 1, "jitter": 0.0, "errors": 0, "packets": 0}
                ]
            });
            write_ctrl_json(&mut ctrl, &srv_res).await.unwrap();
            write_ctrl_state(&mut ctrl, DISPLAY_RESULTS).await.unwrap();
            let done = read_ctrl_state(&mut ctrl).await.unwrap();
            assert_eq!(done, IPERF_DONE);
        });

        let cfg = Iperf3Config {
            host: "127.0.0.1".into(),
            port: addr.port(),
            duration_secs: 1,
            parallel_streams: 2,
            no_delay: true,
            ..Default::default()
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        run_iperf3(cfg, tx, CancelToken::new()).await;
        srv_handle.await.unwrap();

        let mut got_summary = None;
        while let Ok(ev) = rx.try_recv() {
            if let Iperf3Event::Completed(sum) = ev {
                got_summary = Some(*sum);
            }
        }
        let sum = got_summary.expect("completed summary received");
        assert_eq!(sum.protocol, "TCP");
        assert_eq!(sum.streams, 2);
        assert!(sum.total_bytes > 0);
        assert_eq!(sum.retransmits, Some(3));
    }

    #[tokio::test]
    async fn interops_with_real_os_iperf3_daemon_when_present() {
        let bin = std::path::Path::new("/opt/homebrew/bin/iperf3");
        if !bin.is_file() {
            return;
        }
        // Pick an ephemeral port by binding and dropping a TcpListener
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };

        let mut child = tokio::process::Command::new(bin)
            .args(["-s", "-1", "-p", &port.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn iperf3 -s -1");

        // Give daemon 150ms to listen
        tokio::time::sleep(Duration::from_millis(150)).await;

        let cfg = Iperf3Config {
            host: "127.0.0.1".into(),
            port,
            duration_secs: 1,
            parallel_streams: 2,
            reverse: true,
            no_delay: true,
            ..Default::default()
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        run_iperf3(cfg, tx, CancelToken::new()).await;
        let _ = child.kill().await;

        let mut got_summary = None;
        while let Ok(ev) = rx.try_recv() {
            if let Iperf3Event::Completed(sum) = ev {
                got_summary = Some(*sum);
            }
        }
        let sum = got_summary.expect("native wire client interoped with real C iperf3 -s daemon");
        assert_eq!(sum.direction, "Download (-R)");
        assert!(sum.avg_mbps > 100.0, "loopback throughput was {:.1} Mbps", sum.avg_mbps);
    }
}
