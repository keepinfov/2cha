//! Mobile-app onboarding export: the client config as the JSON schema the
//! 2cha Android app imports (`ConfigParser.parseJson` → `VpnConfig`), plus a
//! terminal QR code the app can scan.
//!
//! The JSON deliberately carries **no private key**: the phone generates and
//! keeps its own X25519 identity; its *public* key must be authorized on the
//! server (`[[peers]]` / `2cha peer add`).

use std::net::Ipv4Addr;

use console::style;
use serde_json::json;

/// Everything needed to render a mobile client config.
pub struct MobileExportParams {
    pub endpoint: String,
    pub cipher: String,
    pub server_public_key: String,
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub route_all: bool,
    pub dns_servers: Vec<String>,
    /// "quic", "tls" or "reality"
    pub transport: String,
    pub tls_sni: Option<String>,
    pub reality: Option<RealityMobileParams>,
}

/// REALITY client fields, mirroring the Kotlin app's `RealitySection`
/// (`VpnConfig.kt`): `public_key` / `short_id` / `server_name` / `fingerprint`.
pub struct RealityMobileParams {
    pub public_key: String,
    pub short_id: String,
    pub server_name: String,
    pub fingerprint: String,
}

/// Build the app-importable JSON (field names match the Kotlin `VpnConfig`
/// serialization: snake_case, enum wire values like "chacha20-poly1305").
pub fn mobile_config_json(p: &MobileExportParams) -> String {
    let mut root = json!({
        "client": {
            "server": p.endpoint,
            "transport": p.transport,
            "prefer_ipv6": false,
            "dns_lookup": "auto",
        },
        "tun": { "name": "tun0", "mtu": 1420 },
        "crypto": {
            "cipher": p.cipher,
            "server_public_key": p.server_public_key,
        },
        "ipv4": {
            "enable": true,
            "address": p.address.to_string(),
            "prefix": p.prefix,
            "route_all": p.route_all,
            "routes": [],
            "exclude_ips": [],
        },
        "ipv6": { "enable": false },
        "dns": {
            "servers_v4": p.dns_servers,
            "servers_v6": [],
            "search": [],
        },
    });
    if let Some(ref sni) = p.tls_sni {
        root["tls"] = json!({ "sni": sni });
    }
    if let Some(ref r) = p.reality {
        root["reality"] = json!({
            "public_key": r.public_key,
            "short_id": r.short_id,
            "server_name": r.server_name,
            "fingerprint": r.fingerprint,
        });
    }
    root.to_string()
}

/// Print the mobile onboarding block: QR (TTY only — half-block glyphs are
/// useless in a pipe) plus the raw JSON and the pairing reminder.
pub fn print_mobile_export(name: &str, json: &str, peer_added: bool) {
    println!();
    println!(
        "   {} mobile client {} — scan with the 2cha app:",
        style("◇").cyan(),
        style(name).bold()
    );
    match render_qr(json) {
        Some(qr) if console::Term::stdout().is_term() => {
            println!();
            for line in qr.lines() {
                println!("   {}", line);
            }
            println!();
        }
        _ => println!(
            "   {}",
            style("(no TTY / config too large for a QR — paste the JSON below instead)").dim()
        ),
    }
    println!(
        "   {}",
        style("Config JSON (app: Config → Scan QR, or paste):").dim()
    );
    println!("   {}", json);
    if !peer_added {
        println!(
            "   {} authorize the phone before connecting: {}",
            style("!").yellow().bold(),
            style("2cha peer add <phone-public-key>").cyan()
        );
    }
}

/// Render the JSON as a compact unicode QR (two rows per character cell).
/// Returns None if the payload exceeds QR capacity (should not happen for
/// our configs, which sit well under 1 KiB).
fn render_qr(data: &str) -> Option<String> {
    use qrcode::render::unicode;
    use qrcode::{EcLevel, QrCode};

    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L).ok()?;
    Some(
        code.render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .quiet_zone(true)
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The JSON must match the Android `VpnConfig` schema (snake_case keys,
    /// enum wire values) — this fixture mirrors VpnConfig.kt's @SerialName set.
    #[test]
    fn mobile_json_matches_app_schema() {
        let json = mobile_config_json(&MobileExportParams {
            endpoint: "203.0.113.7:51820".into(),
            cipher: "chacha20-poly1305".into(),
            server_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            address: Ipv4Addr::new(10, 8, 0, 3),
            prefix: 24,
            route_all: true,
            dns_servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            transport: "quic".into(),
            tls_sni: None,
            reality: None,
        });
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["client"]["server"], "203.0.113.7:51820");
        assert_eq!(v["client"]["transport"], "quic");
        assert_eq!(v["client"]["prefer_ipv6"], false);
        assert_eq!(v["client"]["dns_lookup"], "auto");
        assert_eq!(v["crypto"]["cipher"], "chacha20-poly1305");
        assert_eq!(
            v["crypto"]["server_public_key"],
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        assert_eq!(v["ipv4"]["address"], "10.8.0.3");
        assert_eq!(v["ipv4"]["prefix"], 24);
        assert_eq!(v["ipv4"]["route_all"], true);
        assert_eq!(v["dns"]["servers_v4"][0], "1.1.1.1");
        assert_eq!(v["tun"]["mtu"], 1420);
        // No private key may ever ride in the QR
        assert!(!json.contains("private"));
        // tls/reality sections only present for their respective transports
        assert!(v.get("tls").is_none());
        assert!(v.get("reality").is_none());
    }

    #[test]
    fn mobile_json_tls_includes_sni() {
        let json = mobile_config_json(&MobileExportParams {
            endpoint: "vpn.example.com:443".into(),
            cipher: "chacha20-poly1305".into(),
            server_public_key: "k".into(),
            address: Ipv4Addr::new(10, 8, 0, 2),
            prefix: 24,
            route_all: false,
            dns_servers: Vec::new(),
            transport: "tls".into(),
            tls_sni: Some("www.cloudflare.com".into()),
            reality: None,
        });
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["client"]["transport"], "tls");
        assert_eq!(v["tls"]["sni"], "www.cloudflare.com");
    }

    /// The `reality` block must match the Android app's `RealitySection`
    /// (`VpnConfig.kt`) exactly: `public_key`/`short_id`/`server_name`/`fingerprint`.
    #[test]
    fn mobile_json_reality_includes_fields() {
        let json = mobile_config_json(&MobileExportParams {
            endpoint: "vpn.example.com:443".into(),
            cipher: "chacha20-poly1305".into(),
            server_public_key: "k".into(),
            address: Ipv4Addr::new(10, 8, 0, 2),
            prefix: 24,
            route_all: false,
            dns_servers: Vec::new(),
            transport: "reality".into(),
            tls_sni: None,
            reality: Some(RealityMobileParams {
                public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                short_id: "0123456789abcdef".into(),
                server_name: "www.mozilla.org".into(),
                fingerprint: "chrome".into(),
            }),
        });
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["client"]["transport"], "reality");
        assert!(v.get("tls").is_none());
        assert_eq!(
            v["reality"]["public_key"],
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        assert_eq!(v["reality"]["short_id"], "0123456789abcdef");
        assert_eq!(v["reality"]["server_name"], "www.mozilla.org");
        assert_eq!(v["reality"]["fingerprint"], "chrome");
    }

    #[test]
    fn qr_renders_for_typical_config() {
        let json = mobile_config_json(&MobileExportParams {
            endpoint: "203.0.113.7:51820".into(),
            cipher: "chacha20-poly1305".into(),
            server_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            address: Ipv4Addr::new(10, 8, 0, 3),
            prefix: 24,
            route_all: true,
            dns_servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            transport: "quic".into(),
            tls_sni: None,
            reality: None,
        });
        let qr = render_qr(&json).expect("config-sized payloads must fit a QR");
        assert!(qr.lines().count() > 10);
    }
}
