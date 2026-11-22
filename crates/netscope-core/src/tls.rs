use crate::NetError;
use chrono::{DateTime, Utc};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_platform_verifier::Verifier as PlatformVerifier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertDetail {
    pub position_label: String,
    pub subject: String,
    pub subject_cn: String,
    pub issuer: String,
    pub issuer_cn: String,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub is_expired: bool,
    pub is_not_yet_valid: bool,
    pub is_ca: bool,
    pub sans: Vec<String>,
    pub key_algorithm: String,
    pub key_bits: usize,
    pub signature_algorithm: String,
    pub sha256_fingerprint: String,
    pub pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDiagnosis {
    pub os_trusted: bool,
    pub custom_ca_trusted: Option<bool>,
    pub summary: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInspectionResult {
    pub host: String,
    pub port: u16,
    pub sni: String,
    pub protocol_version: String,
    pub cipher_suite: String,
    pub diagnosis: TrustDiagnosis,
    pub chain: Vec<CertDetail>,
}

#[derive(Debug, Default)]
struct CapturedValidation {
    chain_der: Vec<Vec<u8>>,
    os_error: Option<String>,
    custom_ca_error: Option<String>,
    custom_ca_checked: bool,
}

#[derive(Debug)]
struct CapturingCertVerifier {
    os_verifier: Arc<PlatformVerifier>,
    custom_verifier: Option<Arc<WebPkiServerVerifier>>,
    captured: Arc<Mutex<CapturedValidation>>,
}

impl ServerCertVerifier for CapturingCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = Vec::with_capacity(1 + intermediates.len());
        chain.push(end_entity.as_ref().to_vec());
        for inter in intermediates {
            chain.push(inter.as_ref().to_vec());
        }

        let os_res = self.os_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );

        let custom_res = self.custom_verifier.as_ref().map(|cv| {
            cv.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        });

        if let Ok(mut guard) = self.captured.lock() {
            guard.chain_der = chain;
            guard.os_error = os_res.err().map(|e| e.to_string());
            if let Some(cr) = custom_res {
                guard.custom_ca_checked = true;
                guard.custom_ca_error = cr.err().map(|e| e.to_string());
            }
        }

        // Always allow handshake completion so we can expose cipher, protocol, and invalid chain.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.os_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.os_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.os_verifier.supported_verify_schemes()
    }
}

pub async fn inspect_tls(
    host: &str,
    port: u16,
    sni_override: Option<&str>,
    custom_ca_pem_path: Option<&Path>,
) -> Result<TlsInspectionResult, NetError> {
    crate::ensure_crypto_provider();
    let trimmed_host = host.trim();
    if trimmed_host.is_empty() {
        return Err(NetError::InvalidInput("Host cannot be empty".into()));
    }
    let sni_str = sni_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(trimmed_host)
        .to_string();

    let server_name = ServerName::try_from(sni_str.clone())
        .map_err(|e| NetError::InvalidInput(format!("Invalid SNI/hostname '{sni_str}': {e}")))?;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let os_verifier = Arc::new(
        PlatformVerifier::new(provider.clone())
            .map_err(|e| NetError::Tls(format!("OS cert verifier init failed: {e}")))?,
    );

    let custom_verifier = if let Some(ca_path) = custom_ca_pem_path {
        let mut root_store = RootCertStore::empty();
        let iter = CertificateDer::pem_file_iter(ca_path)
            .map_err(|e| NetError::InvalidInput(format!("Cannot read CA PEM file: {e}")))?;
        let mut count = 0usize;
        for cert_res in iter {
            let cert = cert_res
                .map_err(|e| NetError::Parse(format!("Invalid PEM certificate: {e}")))?;
            root_store
                .add(cert)
                .map_err(|e| NetError::Tls(format!("Failed adding custom root CA: {e}")))?;
            count += 1;
        }
        if count == 0 {
            return Err(NetError::InvalidInput(
                "No certificates found in custom CA PEM file".into(),
            ));
        }
        let v = WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider.clone())
            .build()
            .map_err(|e| NetError::Tls(format!("Custom CA verifier build failed: {e}")))?;
        Some(v)
    } else {
        None
    };

    let captured = Arc::new(Mutex::new(CapturedValidation::default()));
    let verifier = Arc::new(CapturingCertVerifier {
        os_verifier,
        custom_verifier,
        captured: captured.clone(),
    });

    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| NetError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let addr = format!("{trimmed_host}:{port}");
    let stream = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(&addr))
        .await
        .map_err(|_| NetError::Timeout)?
        .map_err(NetError::Io)?;

    let tls_stream = tokio::time::timeout(
        Duration::from_secs(8),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| NetError::Timeout)?
    .map_err(|e| NetError::Tls(format!("TLS handshake failed: {e}")))?;

    let (_, conn) = tls_stream.get_ref();
    let protocol_version = conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "Unknown".into());
    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "Unknown".into());

    let snapshot = captured
        .lock()
        .map_err(|_| NetError::Tls("Internal mutex lock error".into()))?;

    let chain_len = snapshot.chain_der.len();
    let mut chain = Vec::with_capacity(chain_len);
    for (idx, der) in snapshot.chain_der.iter().enumerate() {
        chain.push(parse_cert_detail(der, idx, chain_len)?);
    }

    let os_trusted = snapshot.os_error.is_none();
    let custom_ca_trusted = if snapshot.custom_ca_checked {
        Some(snapshot.custom_ca_error.is_none())
    } else {
        None
    };

    let diagnosis = build_trust_diagnosis(
        &sni_str,
        os_trusted,
        snapshot.os_error.as_deref(),
        custom_ca_trusted,
        snapshot.custom_ca_error.as_deref(),
        &chain,
    );

    Ok(TlsInspectionResult {
        host: trimmed_host.to_string(),
        port,
        sni: sni_str,
        protocol_version,
        cipher_suite,
        diagnosis,
        chain,
    })
}

fn parse_cert_detail(der: &[u8], idx: usize, total: usize) -> Result<CertDetail, NetError> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| NetError::Parse(format!("X.509 parse error: {e}")))?;

    let subject = cert.subject().to_string();
    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or(&subject)
        .to_string();

    let issuer = cert.issuer().to_string();
    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or(&issuer)
        .to_string();

    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|ext| ext.value.ca);

    let position_label = if idx == 0 {
        "Leaf".into()
    } else if idx + 1 == total && (subject == issuer || is_ca) {
        if subject == issuer {
            "Root CA".into()
        } else {
            format!("Intermediate #{idx}")
        }
    } else {
        format!("Intermediate #{idx}")
    };

    let validity = cert.validity();
    let now_ts = Utc::now().timestamp();
    let nb_ts = validity.not_before.timestamp();
    let na_ts = validity.not_after.timestamp();

    let not_before = DateTime::<Utc>::from_timestamp(nb_ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| validity.not_before.to_string());
    let not_after = DateTime::<Utc>::from_timestamp(na_ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| validity.not_after.to_string());

    let days_remaining = (na_ts - now_ts) / 86_400;
    let is_expired = now_ts > na_ts;
    let is_not_yet_valid = now_ts < nb_ts;

    let mut sans = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(d) => sans.push((*d).to_string()),
                GeneralName::IPAddress(bytes) => {
                    if bytes.len() == 4 {
                        sans.push(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]));
                    } else if bytes.len() == 16 {
                        let arr: [u8; 16] = (*bytes).try_into().unwrap_or([0; 16]);
                        sans.push(std::net::Ipv6Addr::from(arr).to_string());
                    }
                }
                GeneralName::URI(u) => sans.push((*u).to_string()),
                _ => {}
            }
        }
    }

    let spki = cert.public_key();
    let (key_algorithm, key_bits) = match spki.parsed() {
        Ok(PublicKey::RSA(r)) => ("RSA".into(), r.key_size()),
        Ok(PublicKey::EC(e)) => ("ECDSA".into(), e.key_size()),
        Ok(PublicKey::DSA(d)) => ("DSA".into(), d.len() * 8),
        _ => (spki.algorithm.algorithm.to_id_string(), 0),
    };

    let mut hasher = Sha256::new();
    hasher.update(der);
    let digest = hasher.finalize();
    let fp_hex = hex::encode_upper(digest);
    let sha256_fingerprint = fp_hex
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(":");

    let pem = der_to_pem(der);

    Ok(CertDetail {
        position_label,
        subject,
        subject_cn,
        issuer,
        issuer_cn,
        serial_hex: cert.tbs_certificate.raw_serial_as_string(),
        not_before,
        not_after,
        days_remaining,
        is_expired,
        is_not_yet_valid,
        is_ca,
        sans,
        key_algorithm,
        key_bits,
        signature_algorithm: cert.signature_algorithm.algorithm.to_id_string(),
        sha256_fingerprint,
        pem,
    })
}

fn der_to_pem(der: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::with_capacity(der.len().div_ceil(3) * 4);
    for chunk in der.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        b64.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        b64.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        b64.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        b64.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn build_trust_diagnosis(
    sni: &str,
    os_trusted: bool,
    os_error: Option<&str>,
    custom_ca_trusted: Option<bool>,
    custom_error: Option<&str>,
    chain: &[CertDetail],
) -> TrustDiagnosis {
    let mut reasons = Vec::new();

    for cert in chain {
        if cert.is_expired {
            reasons.push(format!(
                "{} certificate ('{}') expired {} day(s) ago on {}.",
                cert.position_label,
                cert.subject_cn,
                cert.days_remaining.abs(),
                cert.not_after
            ));
        } else if cert.is_not_yet_valid {
            reasons.push(format!(
                "{} certificate ('{}') is not valid until {}.",
                cert.position_label, cert.subject_cn, cert.not_before
            ));
        }
    }

    if let Some(leaf) = chain.first()
        && !leaf.sans.is_empty()
        && !leaf_matches_hostname(&leaf.sans, sni)
    {
        reasons.push(format!(
            "Hostname '{}' does not match any SAN on the leaf certificate ({}).",
            sni,
            leaf.sans.join(", ")
        ));
    }

    if !os_trusted {
        if let Some(leaf) = chain.first()
            && leaf.subject == leaf.issuer
            && chain.len() == 1
        {
            reasons.push("Leaf certificate is self-signed and not trusted by the OS keychain.".into());
        }
        if let Some(err) = os_error {
            reasons.push(format!("OS trust verifier error: {err}"));
        }
    }

    if let Some(false) = custom_ca_trusted
        && let Some(err) = custom_error
    {
        reasons.push(format!("Custom CA verifier error: {err}"));
    }

    let summary = match (os_trusted, custom_ca_trusted) {
        (true, _) => "Certificate chain is valid and trusted by the OS trust store.".into(),
        (false, Some(true)) => {
            "Untrusted by OS default store, but VALID against your supplied Custom CA PEM.".into()
        }
        (false, _) => "Certificate chain is NOT trusted by the OS trust store.".into(),
    };

    TrustDiagnosis {
        os_trusted,
        custom_ca_trusted,
        summary,
        reasons,
    }
}

fn leaf_matches_hostname(sans: &[String], host: &str) -> bool {
    let host_l = host.to_ascii_lowercase();
    sans.iter().any(|san| {
        let san_l = san.to_ascii_lowercase();
        if san_l == host_l {
            return true;
        }
        if let Some(suffix) = san_l.strip_prefix("*.")
            && let Some((_, rest)) = host_l.split_once('.')
        {
            return rest == suffix;
        }
        false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_san_matching_follows_rfc_single_label() {
        let sans = vec!["*.example.com".to_string(), "example.com".to_string()];
        assert!(leaf_matches_hostname(&sans, "example.com"));
        assert!(leaf_matches_hostname(&sans, "app.example.com"));
        assert!(!leaf_matches_hostname(&sans, "a.b.example.com"));
        assert!(!leaf_matches_hostname(&sans, "cloudflare.com"));
    }

    #[tokio::test]
    async fn live_tls_inspect_cloudflare() {
        let res = inspect_tls("cloudflare.com", 443, None, None)
            .await
            .expect("cloudflare.com TLS inspect should succeed");
        assert!(res.diagnosis.os_trusted);
        assert!(!res.chain.is_empty());
        assert!(res.protocol_version.contains("TLS"));
    }
}
