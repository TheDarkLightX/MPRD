use axum::extract::State;
use axum::http::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

#[derive(Clone, Debug)]
pub struct ApiKeyConfig {
    /// If `None`, API key auth is disabled (local dev).
    pub api_key: Option<String>,
}

fn percent_decode(input: &str) -> Option<String> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = (bytes[i + 1] as char).to_digit(16)? as u8;
                let lo = (bytes[i + 2] as char).to_digit(16)? as u8;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn api_key_from_query(req: &Request<axum::body::Body>) -> Option<String> {
    if req.uri().path() != "/api/live" {
        return None;
    }
    let query = req.uri().query()?;
    for part in query.split('&') {
        let (k, v) = match part.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };
        if k == "api_key" {
            return percent_decode(v);
        }
    }
    None
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub async fn require_api_key(
    State(config): State<ApiKeyConfig>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(expected) = config.api_key else {
        return Ok(next.run(req).await);
    };

    let supplied = req
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim);

    let supplied = supplied
        .map(|v| v.to_string())
        .or_else(|| api_key_from_query(&req));

    if supplied
        .as_deref()
        .is_some_and(|s| constant_time_eq(s, expected.trim()))
    {
        return Ok(next.run(req).await);
    }

    // Do not leak whether key was missing vs incorrect.
    Err(StatusCode::UNAUTHORIZED)
}

pub fn api_key_from_env() -> ApiKeyConfig {
    let api_key = std::env::var("MPRD_OPERATOR_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    ApiKeyConfig { api_key }
}

#[cfg(test)]
mod tests {
    use super::{api_key_from_query, constant_time_eq, percent_decode};
    use axum::body::Body;
    use axum::http::Request;

    #[test]
    fn api_key_from_query_skips_malformed_segments() {
        let req = Request::builder()
            .uri("http://localhost/api/live?foo&api_key=secret")
            .body(Body::empty())
            .unwrap();
        assert_eq!(api_key_from_query(&req), Some("secret".to_string()));
    }

    #[test]
    fn api_key_from_query_decodes_percent_encoding() {
        let req = Request::builder()
            .uri("http://localhost/api/live?api_key=a%20b")
            .body(Body::empty())
            .unwrap();
        assert_eq!(api_key_from_query(&req), Some("a b".to_string()));
    }

    #[test]
    fn api_key_from_query_is_disabled_for_non_live_endpoints() {
        let req = Request::builder()
            .uri("http://localhost/api/status?api_key=secret")
            .body(Body::empty())
            .unwrap();
        assert_eq!(api_key_from_query(&req), None);
    }

    #[test]
    fn percent_decode_rejects_invalid_sequences() {
        assert_eq!(percent_decode("%ZZ"), None);
    }

    #[test]
    fn constant_time_eq_behaves_correctly() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }
}
