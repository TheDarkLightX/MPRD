pub use mprd_core::egress::{validate_outbound_url, validate_outbound_url_with_allowlist};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_https_remote() {
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
            mprd_core::MprdError::ConfigError(msg)
                if msg == "Outbound URL must be https, or http only for localhost/loopback"
        ));
    }

    #[test]
    fn rejects_link_local_ip() {
        let err = validate_outbound_url("https://169.254.1.2:8080").expect_err("should reject");
        assert!(matches!(
            err,
            mprd_core::MprdError::ConfigError(msg)
                if msg == "Outbound URL host is a disallowed IP (private/link-local/loopback/multicast/unspecified)"
        ));
    }

    #[test]
    fn rejects_private_ip() {
        let err = validate_outbound_url("https://10.0.0.1:8080").expect_err("should reject");
        assert!(matches!(
            err,
            mprd_core::MprdError::ConfigError(msg)
                if msg == "Outbound URL host is a disallowed IP (private/link-local/loopback/multicast/unspecified)"
        ));
    }
}
