use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeoLocation {
    pub ip: IpAddr,
    pub is_private: bool,
    pub is_anycast: bool,
    /// Detected edge PoP IATA code (e.g. "IST", "AMS", "FRA") or "RTT-Inferred" when clamped by speed-of-light.
    pub anycast_pop: Option<String>,
    /// Original WHOIS/GeoIP registry place before Anycast PoP or speed-of-light correction (e.g. "San Francisco, US").
    pub registry_place: Option<String>,
    pub label: String,
    pub city: Option<String>,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    pub asn: Option<u64>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}

impl GeoLocation {
    pub fn short_place(&self) -> String {
        if self.is_private {
            return self.label.clone();
        }
        let base = match (
            self.city.as_deref().filter(|s| !s.trim().is_empty()),
            self.country_code.as_deref().filter(|s| !s.trim().is_empty()),
            self.country.as_deref().filter(|s| !s.trim().is_empty()),
        ) {
            (Some(c), Some(cc), _) => format!("{c}, {cc}"),
            (Some(c), None, Some(co)) => format!("{c}, {co}"),
            (Some(c), None, None) => c.to_string(),
            (None, Some(cc), _) => cc.to_string(),
            (None, None, Some(co)) => co.to_string(),
            (None, None, None) => self.label.clone(),
        };
        match &self.anycast_pop {
            Some(pop) if pop == "RTT-Edge" => format!("{base} [Anycast Edge]"),
            Some(pop) => format!("{base} [Anycast {pop}]"),
            None if self.is_anycast => format!("{base} [Anycast]"),
            None => base,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IataPop {
    pub code: &'static str,
    pub city: &'static str,
    pub country: &'static str,
    pub country_code: &'static str,
    pub lat: f64,
    pub lon: f64,
}

/// Curated global edge PoP / IXP airport table (Europe, Türkiye, Middle East, North America, APAC).
const IATA_POPS: &[IataPop] = &[
    IataPop { code: "IST", city: "Istanbul", country: "Türkiye", country_code: "TR", lat: 41.0082, lon: 28.9784 },
    IataPop { code: "SAW", city: "Istanbul", country: "Türkiye", country_code: "TR", lat: 40.8986, lon: 29.3092 },
    IataPop { code: "ESB", city: "Ankara", country: "Türkiye", country_code: "TR", lat: 39.9334, lon: 32.8597 },
    IataPop { code: "ADB", city: "Izmir", country: "Türkiye", country_code: "TR", lat: 38.4237, lon: 27.1428 },
    IataPop { code: "SOF", city: "Sofia", country: "Bulgaria", country_code: "BG", lat: 42.6977, lon: 23.3219 },
    IataPop { code: "ATH", city: "Athens", country: "Greece", country_code: "GR", lat: 37.9838, lon: 23.7275 },
    IataPop { code: "OTP", city: "Bucharest", country: "Romania", country_code: "RO", lat: 44.4268, lon: 26.1025 },
    IataPop { code: "BUD", city: "Budapest", country: "Hungary", country_code: "HU", lat: 47.4979, lon: 19.0402 },
    IataPop { code: "VIE", city: "Vienna", country: "Austria", country_code: "AT", lat: 48.2082, lon: 16.3738 },
    IataPop { code: "PRG", city: "Prague", country: "Czechia", country_code: "CZ", lat: 50.0755, lon: 14.4378 },
    IataPop { code: "WAW", city: "Warsaw", country: "Poland", country_code: "PL", lat: 52.2297, lon: 21.0122 },
    IataPop { code: "FRA", city: "Frankfurt", country: "Germany", country_code: "DE", lat: 50.1109, lon: 8.6821 },
    IataPop { code: "MUC", city: "Munich", country: "Germany", country_code: "DE", lat: 48.1351, lon: 11.5820 },
    IataPop { code: "DUS", city: "Düsseldorf", country: "Germany", country_code: "DE", lat: 51.2277, lon: 6.7735 },
    IataPop { code: "BER", city: "Berlin", country: "Germany", country_code: "DE", lat: 52.5200, lon: 13.4050 },
    IataPop { code: "HAM", city: "Hamburg", country: "Germany", country_code: "DE", lat: 53.5511, lon: 9.9937 },
    IataPop { code: "AMS", city: "Amsterdam", country: "Netherlands", country_code: "NL", lat: 52.3676, lon: 4.9041 },
    IataPop { code: "BRU", city: "Brussels", country: "Belgium", country_code: "BE", lat: 50.8503, lon: 4.3517 },
    IataPop { code: "LHR", city: "London", country: "United Kingdom", country_code: "GB", lat: 51.5074, lon: -0.1278 },
    IataPop { code: "MAN", city: "Manchester", country: "United Kingdom", country_code: "GB", lat: 53.4808, lon: -2.2426 },
    IataPop { code: "DUB", city: "Dublin", country: "Ireland", country_code: "IE", lat: 53.3498, lon: -6.2603 },
    IataPop { code: "CDG", city: "Paris", country: "France", country_code: "FR", lat: 48.8566, lon: 2.3522 },
    IataPop { code: "MRS", city: "Marseille", country: "France", country_code: "FR", lat: 43.2965, lon: 5.3698 },
    IataPop { code: "ZRH", city: "Zurich", country: "Switzerland", country_code: "CH", lat: 47.3769, lon: 8.5417 },
    IataPop { code: "GVA", city: "Geneva", country: "Switzerland", country_code: "CH", lat: 46.2044, lon: 6.1432 },
    IataPop { code: "MXP", city: "Milan", country: "Italy", country_code: "IT", lat: 45.4642, lon: 9.1900 },
    IataPop { code: "FCO", city: "Rome", country: "Italy", country_code: "IT", lat: 41.9028, lon: 12.4964 },
    IataPop { code: "MAD", city: "Madrid", country: "Spain", country_code: "ES", lat: 40.4168, lon: -3.7038 },
    IataPop { code: "BCN", city: "Barcelona", country: "Spain", country_code: "ES", lat: 41.3874, lon: 2.1686 },
    IataPop { code: "LIS", city: "Lisbon", country: "Portugal", country_code: "PT", lat: 38.7223, lon: -9.1393 },
    IataPop { code: "CPH", city: "Copenhagen", country: "Denmark", country_code: "DK", lat: 55.6761, lon: 12.5683 },
    IataPop { code: "ARN", city: "Stockholm", country: "Sweden", country_code: "SE", lat: 59.3293, lon: 18.0686 },
    IataPop { code: "OSL", city: "Oslo", country: "Norway", country_code: "NO", lat: 59.9139, lon: 10.7522 },
    IataPop { code: "HEL", city: "Helsinki", country: "Finland", country_code: "FI", lat: 60.1699, lon: 24.9384 },
    IataPop { code: "TBS", city: "Tbilisi", country: "Georgia", country_code: "GE", lat: 41.7151, lon: 44.8271 },
    IataPop { code: "DXB", city: "Dubai", country: "United Arab Emirates", country_code: "AE", lat: 25.2048, lon: 55.2708 },
    IataPop { code: "TLV", city: "Tel Aviv", country: "Israel", country_code: "IL", lat: 32.0853, lon: 34.7818 },
    IataPop { code: "EWR", city: "Newark", country: "United States", country_code: "US", lat: 40.7357, lon: -74.1724 },
    IataPop { code: "JFK", city: "New York", country: "United States", country_code: "US", lat: 40.7128, lon: -74.0060 },
    IataPop { code: "IAD", city: "Ashburn", country: "United States", country_code: "US", lat: 39.0438, lon: -77.4874 },
    IataPop { code: "ORD", city: "Chicago", country: "United States", country_code: "US", lat: 41.8781, lon: -87.6298 },
    IataPop { code: "ATL", city: "Atlanta", country: "United States", country_code: "US", lat: 33.7490, lon: -84.3880 },
    IataPop { code: "MIA", city: "Miami", country: "United States", country_code: "US", lat: 25.7617, lon: -80.1918 },
    IataPop { code: "DFW", city: "Dallas", country: "United States", country_code: "US", lat: 32.7767, lon: -96.7970 },
    IataPop { code: "LAX", city: "Los Angeles", country: "United States", country_code: "US", lat: 34.0522, lon: -118.2437 },
    IataPop { code: "SJC", city: "San Jose", country: "United States", country_code: "US", lat: 37.3382, lon: -121.8863 },
    IataPop { code: "SFO", city: "San Francisco", country: "United States", country_code: "US", lat: 37.7749, lon: -122.4194 },
    IataPop { code: "SEA", city: "Seattle", country: "United States", country_code: "US", lat: 47.6062, lon: -122.3321 },
    IataPop { code: "YYZ", city: "Toronto", country: "Canada", country_code: "CA", lat: 43.6532, lon: -79.3832 },
    IataPop { code: "SIN", city: "Singapore", country: "Singapore", country_code: "SG", lat: 1.3521, lon: 103.8198 },
    IataPop { code: "HKG", city: "Hong Kong", country: "Hong Kong", country_code: "HK", lat: 22.3193, lon: 114.1694 },
    IataPop { code: "NRT", city: "Tokyo", country: "Japan", country_code: "JP", lat: 35.6762, lon: 139.6503 },
    IataPop { code: "SYD", city: "Sydney", country: "Australia", country_code: "AU", lat: -33.8688, lon: 151.2093 },
];

pub fn lookup_iata_pop(code: &str) -> Option<&'static IataPop> {
    let upper = code.trim().to_ascii_uppercase();
    IATA_POPS.iter().find(|p| p.code == upper)
}

/// Known Anycast CDN / DNS provider ASNs whose registry GeoIP often points to US HQ instead of the nearest PoP.
pub fn is_known_anycast_asn(asn: Option<u64>, isp: Option<&str>) -> bool {
    if let Some(a) = asn
        && matches!(
            a,
            13335 | 209242 | 15169 | 16509 | 14618 | 54113 | 20940 | 16625 | 8075 | 32934 | 2906 | 19551 | 396982
        )
    {
        return true;
    }
    if let Some(s) = isp {
        let low = s.to_ascii_lowercase();
        if low.contains("cloudflare")
            || low.contains("fastly")
            || low.contains("akamai")
            || low.contains("cloudfront")
            || low.contains("google")
            || low.contains("quad9")
            || low.contains("nextdns")
            || low.contains("imperva")
        {
            return true;
        }
    }
    false
}

/// Great-circle distance in kilometers between two (lat, lon) coordinates.
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6371.0_f64;
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat * 0.5).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon * 0.5).sin().powi(2);
    let c = 2.0 * a.sqrt().min(1.0).asin();
    r * c
}

/// Minimum physical round-trip time (ms) in optical fiber between two coordinates (~200 km/ms one-way => 100 km/ms RTT).
/// We allow a 0.72 safety margin for GeoIP city centroid imprecision.
pub fn min_physical_rtt_ms(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let dist_km = haversine_km(lat1, lon1, lat2, lon2);
    (dist_km / 100.0) * 0.72
}

/// Validates a hop's GeoLocation against the last physically verified hop coordinate using the speed of light in fiber.
/// If a hop's registry GeoIP claims a location (e.g. San Francisco, US) that is physically impossible for its measured RTT
/// (e.g. 17.5 ms from Türkiye, which cannot exceed ~1,800 km), it clamps the hop's coordinates to the last verified city
/// and marks it as an RTT-inferred Anycast Edge PoP.
pub fn reconcile_hop_with_speed_of_light(
    geo: &mut GeoLocation,
    hop_rtt_ms: Option<f64>,
    anchor_geo: Option<&GeoLocation>,
) -> bool {
    if geo.is_private || geo.anycast_pop.is_some() {
        return false;
    }
    let (Some(rtt), Some(anchor)) = (hop_rtt_ms, anchor_geo) else {
        return false;
    };
    let (Some(lat1), Some(lon1), Some(lat2), Some(lon2)) =
        (anchor.lat, anchor.lon, geo.lat, geo.lon)
    else {
        return false;
    };

    let dist_km = haversine_km(lat1, lon1, lat2, lon2);
    if dist_km < 1200.0 {
        return false;
    }
    let min_rtt = min_physical_rtt_ms(lat1, lon1, lat2, lon2);
    // If total RTT from origin is smaller than the physical minimum RTT required just to bridge anchor -> geo
    if rtt + 8.0 < min_rtt {
        let reg = match (&geo.city, &geo.country_code) {
            (Some(c), Some(cc)) if !c.is_empty() => format!("{c}, {cc}"),
            (None, Some(cc)) => cc.clone(),
            _ => "Registry HQ".into(),
        };
        geo.registry_place = Some(reg);
        geo.is_anycast = true;
        geo.anycast_pop = Some("RTT-Edge".into());
        geo.city = anchor.city.clone();
        geo.country = anchor.country.clone();
        geo.country_code = anchor.country_code.clone();
        geo.lat = anchor.lat;
        geo.lon = anchor.lon;
        return true;
    }
    false
}

#[derive(Debug, Deserialize)]
struct IpWhoIsResp {
    success: Option<bool>,
    country: Option<String>,
    country_code: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    connection: Option<IpWhoIsConn>,
}

#[derive(Debug, Deserialize)]
struct IpWhoIsConn {
    asn: Option<u64>,
    isp: Option<String>,
    org: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpGuideResp {
    network: Option<IpGuideNetwork>,
    location: Option<IpGuideLocation>,
}

#[derive(Debug, Deserialize)]
struct IpGuideNetwork {
    autonomous_system: Option<IpGuideAs>,
}

#[derive(Debug, Deserialize)]
struct IpGuideAs {
    asn: Option<u64>,
    name: Option<String>,
    organization: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpGuideLocation {
    city: Option<String>,
    country: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct RipeGeoResp {
    status: Option<String>,
    data: Option<RipeGeoData>,
}

#[derive(Debug, Deserialize)]
struct RipeGeoData {
    located_resources: Option<Vec<RipeLocatedResource>>,
}

#[derive(Debug, Deserialize)]
struct RipeLocatedResource {
    locations: Option<Vec<RipeLocationEntry>>,
}

#[derive(Debug, Deserialize)]
struct RipeLocationEntry {
    country: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn valid_coords(lat: Option<f64>, lon: Option<f64>) -> (Option<f64>, Option<f64>) {
    match (lat, lon) {
        (Some(la), Some(lo))
            if la.is_finite() && lo.is_finite() && !(la.abs() < 1e-6 && lo.abs() < 1e-6) =>
        {
            (Some(la), Some(lo))
        }
        _ => (None, None),
    }
}

fn default_public_geo(ip: IpAddr) -> GeoLocation {
    GeoLocation {
        ip,
        is_private: false,
        is_anycast: false,
        anycast_pop: None,
        registry_place: None,
        label: "Public IP".into(),
        city: None,
        country: None,
        country_code: None,
        isp: None,
        asn: None,
        lat: None,
        lon: None,
    }
}

fn parse_ip_guide(ip: IpAddr, data: IpGuideResp) -> GeoLocation {
    let (asn, isp) = match data.network.and_then(|n| n.autonomous_system) {
        Some(a) => (a.asn, non_empty(a.organization).or_else(|| non_empty(a.name))),
        None => (None, None),
    };
    let is_anycast = is_known_anycast_asn(asn, isp.as_deref());
    let (city, country, lat, lon) = match data.location {
        Some(l) => {
            let (lat, lon) = valid_coords(l.latitude, l.longitude);
            (non_empty(l.city), non_empty(l.country), lat, lon)
        }
        None => (None, None, None, None),
    };

    GeoLocation {
        ip,
        is_private: false,
        is_anycast,
        anycast_pop: None,
        registry_place: None,
        label: "Public IP".into(),
        city,
        country,
        // Intentionally do not copy autonomous_system.country into country_code:
        // multinational transit ASes route traffic across many countries.
        country_code: None,
        isp,
        asn,
        lat,
        lon,
    }
}

fn apply_ripe_geo(loc: &mut GeoLocation, resp: RipeGeoResp) -> bool {
    if resp.status.as_deref().is_some_and(|s| s != "ok") {
        return false;
    }
    let Some(entry) = resp
        .data
        .and_then(|d| d.located_resources)
        .and_then(|mut rs| rs.drain(..).next())
        .and_then(|r| r.locations)
        .and_then(|mut ls| ls.drain(..).next())
    else {
        return false;
    };

    if entry.country.as_deref().map(str::trim) == Some("?") {
        return false;
    }
    let (Some(lat), Some(lon)) = valid_coords(entry.latitude, entry.longitude) else {
        return false;
    };

    loc.lat = Some(lat);
    loc.lon = Some(lon);
    if loc.city.as_deref().is_none_or(|s| s.trim().is_empty()) {
        loc.city = non_empty(entry.city);
    }
    if loc
        .country_code
        .as_deref()
        .is_none_or(|s| s.trim().is_empty())
    {
        loc.country_code = non_empty(entry.country);
    }
    true
}

static GEO_CACHE: OnceLock<Arc<Mutex<HashMap<IpAddr, GeoLocation>>>> = OnceLock::new();

fn cache() -> &'static Arc<Mutex<HashMap<IpAddr, GeoLocation>>> {
    GEO_CACHE.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

/// Checks non-global / RFC1918 / CGNAT IP space locally so private hops never leave the host.
pub fn classify_local_ip(ip: IpAddr) -> Option<GeoLocation> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4).map(|label| GeoLocation {
            ip,
            is_private: true,
            is_anycast: false,
            anycast_pop: None,
            registry_place: None,
            label: label.to_string(),
            city: None,
            country: None,
            country_code: None,
            isp: None,
            asn: None,
            lat: None,
            lon: None,
        }),
        IpAddr::V6(v6) => classify_v6(v6).map(|label| GeoLocation {
            ip,
            is_private: true,
            is_anycast: false,
            anycast_pop: None,
            registry_place: None,
            label: label.to_string(),
            city: None,
            country: None,
            country_code: None,
            isp: None,
            asn: None,
            lat: None,
            lon: None,
        }),
    }
}

fn classify_v4(ip: Ipv4Addr) -> Option<&'static str> {
    let o = ip.octets();
    if ip.is_loopback() {
        return Some("Loopback");
    }
    if ip.is_private() {
        return Some("Local LAN (RFC 1918)");
    }
    if ip.is_link_local() {
        return Some("Link-Local");
    }
    // RFC 6598 Shared Address Space (100.64.0.0/10) — CGNAT or Tailscale
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return Some("CGNAT / Tailscale (100.64/10)");
    }
    if ip.is_multicast() || ip.is_broadcast() || ip.is_unspecified() {
        return Some("Reserved");
    }
    None
}

fn classify_v6(ip: Ipv6Addr) -> Option<&'static str> {
    if ip.is_loopback() {
        return Some("Loopback");
    }
    if ip.is_unicast_link_local() {
        return Some("Link-Local");
    }
    let seg0 = ip.segments()[0];
    // fc00::/7 Unique Local Address
    if (seg0 & 0xfe00) == 0xfc00 {
        return Some("Unique Local (ULA)");
    }
    None
}

/// Probes an Anycast IP over HTTP (:80) to extract its real serving Edge PoP IATA code
/// from `CF-RAY` (Cloudflare), `x-served-by` (Fastly), or `x-amz-cf-pop` (CloudFront).
pub async fn probe_anycast_http_pop(client: &reqwest::Client, ip: IpAddr) -> Option<&'static IataPop> {
    let url = match ip {
        IpAddr::V4(v4) => format!("http://{v4}/"),
        IpAddr::V6(v6) => format!("http://[{v6}]/"),
    };
    let resp = client
        .head(&url)
        .timeout(Duration::from_millis(1200))
        .send()
        .await
        .ok()?;
    let headers = resp.headers();

    // 1. Cloudflare: CF-RAY: <id>-IST
    if let Some(ray) = headers.get("cf-ray").and_then(|v| v.to_str().ok())
        && let Some((_, iata)) = ray.rsplit_once('-')
        && let Some(pop) = lookup_iata_pop(iata)
    {
        return Some(pop);
    }

    // 2. CloudFront: x-amz-cf-pop: FRA56-P2 -> first 3 letters
    if let Some(cf) = headers.get("x-amz-cf-pop").and_then(|v| v.to_str().ok())
        && cf.len() >= 3
        && let Some(pop) = lookup_iata_pop(&cf[..3])
    {
        return Some(pop);
    }

    // 3. Fastly: x-served-by: cache-ams21001-AMS -> last 3 letters after '-'
    if let Some(served) = headers.get("x-served-by").and_then(|v| v.to_str().ok())
        && let Some((_, tail)) = served.rsplit_once('-')
        && tail.len() >= 3
        && let Some(pop) = lookup_iata_pop(&tail[..3])
    {
        return Some(pop);
    }

    None
}

fn apply_anycast_pop(loc: &mut GeoLocation, pop: &'static IataPop) {
    let reg = match (
        loc.city.as_deref().filter(|s| !s.trim().is_empty()),
        loc.country_code.as_deref().filter(|s| !s.trim().is_empty()),
        loc.country.as_deref().filter(|s| !s.trim().is_empty()),
    ) {
        (Some(c), Some(cc), _) => Some(format!("{c}, {cc}")),
        (Some(c), None, Some(co)) => Some(format!("{c}, {co}")),
        (None, Some(cc), _) => Some(cc.to_string()),
        (None, None, Some(co)) => Some(co.to_string()),
        _ => None,
    };
    loc.registry_place = reg;
    loc.is_anycast = true;
    loc.anycast_pop = Some(pop.code.to_string());
    loc.city = Some(pop.city.to_string());
    loc.country = Some(pop.country.to_string());
    loc.country_code = Some(pop.country_code.to_string());
    loc.lat = Some(pop.lat);
    loc.lon = Some(pop.lon);
}

fn should_probe_anycast_early(loc: &GeoLocation) -> bool {
    loc.is_anycast
        || loc.country_code.as_deref() == Some("US")
        || loc.country.as_deref() == Some("United States")
}

/// Resolves geographic coordinates & ISP/ASN metadata for an IP with multi-provider fallbacks, Anycast Edge PoP detection, and strict OPSEC.
pub async fn lookup_ip(ip: IpAddr) -> GeoLocation {
    if let Some(local) = classify_local_ip(ip) {
        return local;
    }

    if let Some(hit) = cache().lock().await.get(&ip).cloned() {
        return hit;
    }

    crate::ensure_crypto_provider();
    let fallback = default_public_geo(ip);

    let Ok(client) = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(4))
        .user_agent("NetScope/0.3")
        .build()
    else {
        return fallback;
    };

    // Provider 1: ipwho.is (may be DNS-sinkholed to 0.0.0.0 by AdGuard / Pi-hole)
    let mut loc = match client.get(format!("https://ipwho.is/{ip}")).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<IpWhoIsResp>().await {
            Ok(data) if data.success.unwrap_or(false) => {
                let (asn, isp) = match data.connection {
                    Some(c) => (c.asn, non_empty(c.isp).or_else(|| non_empty(c.org))),
                    None => (None, None),
                };
                let anycast = is_known_anycast_asn(asn, isp.as_deref());
                let (lat, lon) = valid_coords(data.latitude, data.longitude);
                GeoLocation {
                    ip,
                    is_private: false,
                    is_anycast: anycast,
                    anycast_pop: None,
                    registry_place: None,
                    label: "Public IP".into(),
                    city: non_empty(data.city),
                    country: non_empty(data.country),
                    country_code: non_empty(data.country_code),
                    isp,
                    asn,
                    lat,
                    lon,
                }
            }
            _ => default_public_geo(ip),
        },
        _ => default_public_geo(ip),
    };

    // Provider 2: ip.guide (privacy-friendly, not on standard adblock lists)
    if loc.lat.is_none()
        && loc.asn.is_none()
        && let Ok(resp) = client.get(format!("https://ip.guide/{ip}")).send().await
        && resp.status().is_success()
        && let Ok(data) = resp.json::<IpGuideResp>().await
    {
        loc = parse_ip_guide(ip, data);
    }

    // Early Anycast Edge PoP probe before Provider 3 so Cloudflare/Fastly/CloudFront IPs resolve directly in ~20ms
    let mut probed_http = false;
    if should_probe_anycast_early(&loc) {
        probed_http = true;
        if let Some(pop) = probe_anycast_http_pop(&client, ip).await {
            apply_anycast_pop(&mut loc, pop);
        }
    }

    // Provider 3: RIPEstat MaxMind GeoLite2 (official RIR endpoint, fills unlocated non-Anycast hops while preserving ip.guide ASN/ISP)
    if loc.lat.is_none()
        && let Ok(resp) = client
            .get(format!(
                "https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource={ip}"
            ))
            .send()
            .await
        && resp.status().is_success()
        && let Ok(data) = resp.json::<RipeGeoResp>().await
    {
        apply_ripe_geo(&mut loc, data);
    }

    // Fallback Anycast HTTP probe if RIPEstat returned US or location is still unmapped
    if !probed_http
        && (should_probe_anycast_early(&loc) || loc.lat.is_none())
        && let Some(pop) = probe_anycast_http_pop(&client, ip).await
    {
        apply_anycast_pop(&mut loc, pop);
    }

    if loc.lat.is_some() {
        cache().lock().await.insert(ip, loc.clone());
    }
    loc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_rfc1918_and_cgnat_without_network() {
        let lan: IpAddr = "192.168.1.1".parse().unwrap();
        let cgnat: IpAddr = "100.64.0.1".parse().unwrap();
        let pub_ip: IpAddr = "1.1.1.1".parse().unwrap();

        let g_lan = classify_local_ip(lan).expect("192.168.1.1 is private");
        assert!(g_lan.is_private);
        assert!(g_lan.label.contains("LAN"));

        let g_cg = classify_local_ip(cgnat).expect("100.64.0.1 is CGNAT");
        assert!(g_cg.is_private);
        assert!(g_cg.label.contains("CGNAT"));

        assert!(classify_local_ip(pub_ip).is_none());
    }

    #[test]
    fn speed_of_light_clamps_impossible_transatlantic_geoip() {
        let istanbul = GeoLocation {
            ip: "212.156.120.159".parse().unwrap(),
            is_private: false,
            is_anycast: false,
            anycast_pop: None,
            registry_place: None,
            label: "Public IP".into(),
            city: Some("Istanbul".into()),
            country: Some("Türkiye".into()),
            country_code: Some("TR".into()),
            isp: Some("Turk Telekom".into()),
            asn: Some(9121),
            lat: Some(41.0082),
            lon: Some(28.9784),
        };
        let mut fake_sf = GeoLocation {
            ip: "104.16.132.229".parse().unwrap(),
            is_private: false,
            is_anycast: true,
            anycast_pop: None,
            registry_place: None,
            label: "Public IP".into(),
            city: Some("San Francisco".into()),
            country: Some("United States".into()),
            country_code: Some("US".into()),
            isp: Some("Cloudflare, Inc.".into()),
            asn: Some(13335),
            lat: Some(37.7749),
            lon: Some(-122.4194),
        };

        // 17.5 ms from Istanbul to San Francisco (~10,800 km) violates speed of light in fiber (>77 ms min)
        let clamped =
            reconcile_hop_with_speed_of_light(&mut fake_sf, Some(17.5), Some(&istanbul));
        assert!(clamped);
        assert_eq!(fake_sf.city.as_deref(), Some("Istanbul"));
        assert_eq!(fake_sf.country_code.as_deref(), Some("TR"));
        assert_eq!(fake_sf.anycast_pop.as_deref(), Some("RTT-Edge"));
        assert_eq!(
            fake_sf.registry_place.as_deref(),
            Some("San Francisco, US")
        );
    }

    #[test]
    fn parses_ip_guide_response_and_formats_short_place() {
        let regular_json = r#"{
            "ip": "212.156.120.159",
            "network": {
                "autonomous_system": {
                    "asn": 9121,
                    "name": "TTNet",
                    "organization": "Turk Telekom",
                    "country": "TR"
                }
            },
            "location": {
                "city": "Istanbul",
                "country": "Türkiye",
                "latitude": 41.0108,
                "longitude": 28.9482
            }
        }"#;
        let parsed: IpGuideResp = serde_json::from_str(regular_json).unwrap();
        let loc = parse_ip_guide("212.156.120.159".parse().unwrap(), parsed);
        assert_eq!(loc.asn, Some(9121));
        assert_eq!(loc.isp.as_deref(), Some("Turk Telekom"));
        assert!(!loc.is_anycast);
        assert_eq!(loc.city.as_deref(), Some("Istanbul"));
        assert_eq!(loc.country.as_deref(), Some("Türkiye"));
        assert_eq!(loc.country_code, None);
        assert_eq!(loc.lat, Some(41.0108));
        assert_eq!(loc.lon, Some(28.9482));
        assert_eq!(loc.short_place(), "Istanbul, Türkiye");

        let anycast_json = r#"{
            "ip": "1.1.1.1",
            "network": {
                "autonomous_system": {
                    "asn": 13335,
                    "name": "CLOUDFLARENET",
                    "organization": "Cloudflare, Inc.",
                    "country": "US"
                }
            },
            "location": {
                "city": null,
                "country": null,
                "latitude": null,
                "longitude": null
            }
        }"#;
        let parsed_cf: IpGuideResp = serde_json::from_str(anycast_json).unwrap();
        let loc_cf = parse_ip_guide("1.1.1.1".parse().unwrap(), parsed_cf);
        assert_eq!(loc_cf.asn, Some(13335));
        assert_eq!(loc_cf.isp.as_deref(), Some("Cloudflare, Inc."));
        assert!(loc_cf.is_anycast);
        assert_eq!(loc_cf.lat, None);
        assert_eq!(loc_cf.lon, None);
    }

    #[test]
    fn ripe_geo_rejects_null_island_and_parses_valid_location() {
        let mut loc = GeoLocation {
            ip: "198.51.100.10".parse().unwrap(),
            is_private: false,
            is_anycast: false,
            anycast_pop: None,
            registry_place: None,
            label: "Public IP".into(),
            city: None,
            country: None,
            country_code: None,
            isp: Some("Arelion".into()),
            asn: Some(1299),
            lat: None,
            lon: None,
        };

        let null_island_json = r#"{
            "status": "ok",
            "data": {
                "located_resources": [{
                    "locations": [{
                        "country": "?",
                        "city": "",
                        "latitude": 0.0,
                        "longitude": 0.0
                    }]
                }]
            }
        }"#;
        let bad_resp: RipeGeoResp = serde_json::from_str(null_island_json).unwrap();
        assert!(!apply_ripe_geo(&mut loc, bad_resp));
        assert_eq!(loc.lat, None);
        assert_eq!(loc.country_code, None);

        let valid_json = r#"{
            "status": "ok",
            "data": {
                "located_resources": [{
                    "locations": [{
                        "country": "FR",
                        "city": "",
                        "latitude": 48.8582,
                        "longitude": 2.3387
                    }]
                }]
            }
        }"#;
        let good_resp: RipeGeoResp = serde_json::from_str(valid_json).unwrap();
        assert!(apply_ripe_geo(&mut loc, good_resp));
        assert_eq!(loc.lat, Some(48.8582));
        assert_eq!(loc.lon, Some(2.3387));
        assert_eq!(loc.city, None);
        assert_eq!(loc.country_code.as_deref(), Some("FR"));
        // Preserves pre-populated ASN & ISP from ip.guide
        assert_eq!(loc.asn, Some(1299));
        assert_eq!(loc.isp.as_deref(), Some("Arelion"));
        assert_eq!(loc.short_place(), "FR");
    }

    #[tokio::test]
    async fn live_geoip_lookup_one_one_one_one() {
        let loc = lookup_ip("1.1.1.1".parse().unwrap()).await;
        assert!(!loc.is_private);
        assert!(loc.lat.is_some() && loc.lon.is_some());
        assert!(loc.is_anycast);
    }
}
