use crate::{MprdError, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

const MAX_RESOLVED_ADDRS: usize = 8;

fn is_loopback_host(host: &str) -> bool {
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

    if host.parse::<IpAddr>().is_ok_and(is_disallowed_ip) {
        return Err(MprdError::ConfigError(
            "Outbound URL host is a disallowed IP (private/link-local/loopback/multicast/unspecified)".into(),
        ));
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
        assert!(err.to_string().contains("https"));
    }

    #[test]
    fn rejects_link_local_ip() {
        let err = validate_outbound_url("https://169.254.1.2:8080").expect_err("should reject");
        assert!(err.to_string().to_lowercase().contains("disallowed"));
    }

    #[test]
    fn rejects_private_ip() {
        let err = validate_outbound_url("https://10.0.0.1:8080").expect_err("should reject");
        assert!(err.to_string().to_lowercase().contains("disallowed"));
    }
}
