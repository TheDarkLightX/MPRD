//! Outbound URL validation for SSRF prevention.
//!
//! # Security Model
//!
//! This module provides centralized validation for outbound URLs to prevent
//! Server-Side Request Forgery (SSRF) attacks. All outbound HTTP requests
//! MUST be validated through `validate_outbound_url` before execution.
//!
//! # DNS Rebinding Warning
//!
//! **TOCTOU Risk**: There is a time-of-check-to-time-of-use gap between
//! URL validation and the actual HTTP request. A sophisticated attacker
//! could exploit DNS rebinding:
//!
//! 1. Attacker controls DNS for `evil.com`
//! 2. First DNS query (during validation) returns `1.2.3.4` (allowed)
//! 3. Second DNS query (during HTTP request) returns `10.0.0.1` (internal)
//! 4. Request goes to internal network
//!
//! # Mitigations
//!
//! For high-security deployments, consider:
//!
//! 1. **IP Pinning**: Resolve DNS once and use the IP directly in requests
//!    via reqwest's `resolve()` method
//! 2. **Short DNS TTL Rejection**: Reject responses with TTL < threshold
//! 3. **Network Isolation**: Run MPRD in a network segment without internal access
//! 4. **Egress Proxy**: Route all outbound through a validating proxy
//!
//! The current implementation provides defense-in-depth but cannot fully
//! prevent DNS rebinding without IP pinning at the HTTP client level.

use crate::{MprdError, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

const MAX_RESOLVED_ADDRS: usize = 8;

fn strip_ipv6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

fn is_loopback_host(host: &str) -> bool {
    let host = strip_ipv6_brackets(host);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn is_disallowed_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_link_local()
        || ip.is_private()
        || ip.is_multicast()
        || ip.is_broadcast()
}

fn is_disallowed_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_unicast_link_local()
        || ip.is_unique_local()
        || ip.is_multicast()
}

fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_disallowed_ipv4(v4),
        IpAddr::V6(v6) => is_disallowed_ipv6(v6),
    }
}

fn validate_scheme(scheme: &str, host: &str) -> Result<()> {
    if scheme == "https" {
        return Ok(());
    }

    if scheme == "http" && is_loopback_host(host) {
        return Ok(());
    }

    Err(MprdError::ConfigError(
        "Outbound URL must be https, or http only for localhost/loopback".into(),
    ))
}

fn host_is_allowlisted(host: &str, allowlist: &[String]) -> bool {
    allowlist
        .iter()
        .any(|entry| entry.eq_ignore_ascii_case(host))
}

fn validate_resolved_host(host: &str, port: u16) -> Result<()> {
    let mut resolved_any = false;

    for addr in (host, port)
        .to_socket_addrs()
        .map_err(|e| MprdError::ConfigError(format!("Failed to resolve host: {e}")))?
        .take(MAX_RESOLVED_ADDRS)
    {
        resolved_any = true;
        if is_disallowed_ip(addr.ip()) {
            return Err(MprdError::ConfigError(
                "Outbound URL resolves to a disallowed IP (private/link-local/loopback/multicast/unspecified)".into(),
            ));
        }
    }

    if resolved_any {
        return Ok(());
    }

    Err(MprdError::ConfigError(
        "Outbound URL host did not resolve to any IP addresses".into(),
    ))
}

pub fn validate_outbound_url(raw: &str) -> Result<url::Url> {
    validate_outbound_url_with_allowlist(raw, &[])
}

pub fn validate_outbound_url_with_allowlist(
    raw: &str,
    allowed_hosts: &[String],
) -> Result<url::Url> {
    let url =
        url::Url::parse(raw).map_err(|e| MprdError::ConfigError(format!("Invalid URL: {e}")))?;

    if url.username() != "" || url.password().is_some() {
        return Err(MprdError::ConfigError(
            "Outbound URL must not contain userinfo".into(),
        ));
    }

    if url.fragment().is_some() {
        return Err(MprdError::ConfigError(
            "Outbound URL must not contain a fragment".into(),
        ));
    }

    let Some(host) = url.host_str() else {
        return Err(MprdError::ConfigError(
            "Outbound URL must include a host".into(),
        ));
    };

    validate_scheme(url.scheme(), host)?;

    if is_loopback_host(host) {
        return Ok(url);
    }

    if host_is_allowlisted(host, allowed_hosts) {
        return Ok(url);
    }

    let host_for_ip = strip_ipv6_brackets(host);
    if let Ok(ip) = host_for_ip.parse::<IpAddr>() {
        if is_disallowed_ip(ip) {
            return Err(MprdError::ConfigError(
                "Outbound URL host is a disallowed IP (private/link-local/loopback/multicast/unspecified)".into(),
            ));
        }
        return Ok(url);
    }

    let port = url.port_or_known_default().ok_or_else(|| {
        MprdError::ConfigError("Outbound URL must include a port or known default".into())
    })?;

    validate_resolved_host(host, port)?;

    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn allows_https_ip() {
        validate_outbound_url("https://1.1.1.1").expect("https should be allowed");
    }

    #[test]
    fn allows_http_localhost() {
        validate_outbound_url("http://localhost:5001").expect("localhost http should be allowed");
    }

    #[test]
    fn rejects_http_remote() {
        let err = validate_outbound_url("http://example.com").expect_err("should reject");
        assert!(matches!(
            err,
            MprdError::ConfigError(msg)
                if msg == "Outbound URL must be https, or http only for localhost/loopback"
        ));
    }

    #[test]
    fn rejects_link_local_ip() {
        let err = validate_outbound_url("https://169.254.1.2:8080").expect_err("should reject");
        assert!(matches!(
            err,
            MprdError::ConfigError(msg)
                if msg == "Outbound URL host is a disallowed IP (private/link-local/loopback/multicast/unspecified)"
        ));
    }

    #[test]
    fn rejects_private_ip() {
        let err = validate_outbound_url("https://10.0.0.1:8080").expect_err("should reject");
        assert!(matches!(
            err,
            MprdError::ConfigError(msg)
                if msg == "Outbound URL host is a disallowed IP (private/link-local/loopback/multicast/unspecified)"
        ));
    }

    #[test]
    fn rejects_unique_local_ipv6() {
        let err = validate_outbound_url("https://[fc00::1]:8080").expect_err("should reject");
        assert!(matches!(
            err,
            MprdError::ConfigError(msg)
                if msg == "Outbound URL host is a disallowed IP (private/link-local/loopback/multicast/unspecified)"
        ));
    }

    #[test]
    fn rejects_link_local_ipv6() {
        let err = validate_outbound_url("https://[fe80::1]:8080").expect_err("should reject");
        assert!(matches!(
            err,
            MprdError::ConfigError(msg)
                if msg == "Outbound URL host is a disallowed IP (private/link-local/loopback/multicast/unspecified)"
        ));
    }

    #[test]
    fn rejects_unspecified_ipv6() {
        let err = validate_outbound_url("https://[::]:8080").expect_err("should reject");
        assert!(matches!(
            err,
            MprdError::ConfigError(msg)
                if msg == "Outbound URL host is a disallowed IP (private/link-local/loopback/multicast/unspecified)"
        ));
    }

    #[test]
    fn allows_https_global_ipv6() {
        validate_outbound_url("https://[2001:4860:4860::8888]")
            .expect("ipv6 global should be allowed");
    }

    #[test]
    fn allowlisted_host_bypasses_dns_resolution() {
        let allow = vec!["does-not-exist.invalid".to_string()];
        validate_outbound_url_with_allowlist("https://does-not-exist.invalid", &allow)
            .expect("allowlisted host should be allowed");
    }

    #[test]
    fn allowlist_is_case_insensitive() {
        let allow = vec!["EXAMPLE.COM".to_string()];
        validate_outbound_url_with_allowlist("https://example.com", &allow)
            .expect("allowlisted host should match case-insensitively");
    }

    #[test]
    fn allowlist_does_not_allow_http_remote() {
        let allow = vec!["example.com".to_string()];
        let err = validate_outbound_url_with_allowlist("http://example.com", &allow)
            .expect_err("should reject");
        assert!(matches!(
            err,
            MprdError::ConfigError(msg)
                if msg == "Outbound URL must be https, or http only for localhost/loopback"
        ));
    }

    fn private_v4() -> impl Strategy<Value = Ipv4Addr> {
        prop_oneof![
            // 10.0.0.0/8
            (0u8..=255, 0u8..=255, 0u8..=255).prop_map(|(b, c, d)| Ipv4Addr::new(10, b, c, d)),
            // 172.16.0.0/12
            (16u8..=31, 0u8..=255, 0u8..=255).prop_map(|(b, c, d)| Ipv4Addr::new(172, b, c, d)),
            // 192.168.0.0/16
            (0u8..=255, 0u8..=255).prop_map(|(c, d)| Ipv4Addr::new(192, 168, c, d)),
        ]
    }

    proptest! {
        #[test]
        fn rejects_private_ipv4_over_https(ip in private_v4(), port in 1u16..=65535) {
            let url = format!("https://{ip}:{port}");
            prop_assert!(validate_outbound_url(&url).is_err());
        }

        #[test]
        fn rejects_link_local_ipv4_over_https(b in 0u8..=255, c in 0u8..=255, port in 1u16..=65535) {
            let ip = Ipv4Addr::new(169, 254, b, c);
            let url = format!("https://{ip}:{port}");
            prop_assert!(validate_outbound_url(&url).is_err());
        }

        #[test]
        fn allows_http_loopback(ip in any::<[u8; 4]>(), port in 1u16..=65535) {
            // Any 127.0.0.0/8 address is loopback.
            let ip = Ipv4Addr::new(127, ip[1], ip[2], ip[3]);
            let url = format!("http://{ip}:{port}");
            prop_assert!(validate_outbound_url(&url).is_ok());
        }
    }
}
