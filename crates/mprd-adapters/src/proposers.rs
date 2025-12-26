use mprd_core::egress::validate_outbound_url;
use mprd_core::hash::hash_candidate;
use mprd_core::validation::validate_candidate_action_v1;
use mprd_core::{
    CandidateAction, Hash32, MprdError, PolicyHash, Proposer, Result, Score, StateSnapshot, Value,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Maximum response body size from proposer endpoints (DoS prevention).
const MAX_RESPONSE_BYTES: usize = 1024 * 1024; // 1 MiB

trait HttpPoster: Send + Sync {
    fn post_json_bytes(&self, url: &str, body: &[u8]) -> Result<HttpResponse>;
}

#[derive(Debug, Clone)]
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

struct ReqwestHttpPoster {
    client: reqwest::blocking::Client,
}

impl ReqwestHttpPoster {
    fn new(timeout: Duration) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|e| {
                MprdError::ExecutionError(format!("Failed to create HTTP client: {}", e))
            })?;
        Ok(Self { client })
    }
}

impl HttpPoster for ReqwestHttpPoster {
    fn post_json_bytes(&self, url: &str, body: &[u8]) -> Result<HttpResponse> {
        let response = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .map_err(|e| {
                MprdError::ExecutionError(format!("HTTP proposer request failed: {}", e))
            })?;

        let status = response.status().as_u16();

        // Check Content-Length before reading body (DoS prevention fast path)
        if let Some(content_length) = response.content_length() {
            if content_length > MAX_RESPONSE_BYTES as u64 {
                return Err(MprdError::BoundedValueExceeded(format!(
                    "proposer response too large: {} bytes (max {})",
                    content_length, MAX_RESPONSE_BYTES
                )));
            }
        }

        // Bounded streaming read: stop reading if we exceed the limit (handles chunked encoding)
        use std::io::Read;
        let mut limited_reader = response.take((MAX_RESPONSE_BYTES + 1) as u64);
        let mut buf = Vec::with_capacity(MAX_RESPONSE_BYTES);
        limited_reader.read_to_end(&mut buf).map_err(|e| {
            MprdError::ExecutionError(format!("Failed to read proposer response: {}", e))
        })?;

        // Check if we hit the limit
        if buf.len() > MAX_RESPONSE_BYTES {
            return Err(MprdError::BoundedValueExceeded(format!(
                "proposer response too large: >{} bytes (max {})",
                MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES
            )));
        }

        Ok(HttpResponse { status, body: buf })
    }
}

#[derive(Debug, Clone)]
pub struct HttpProposerConfig {
    pub base_url: String,
    pub endpoint_path: String,
    pub timeout: Duration,
    pub max_candidates: usize,
}

impl Default for HttpProposerConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:8081".into(),
            endpoint_path: "/api/v1/propose".into(),
            timeout: Duration::from_secs(10),
            max_candidates: mprd_core::MAX_CANDIDATES,
        }
    }
}

pub struct HttpProposer {
    config: HttpProposerConfig,
    http: Box<dyn HttpPoster>,
    policy_hash: PolicyHash,
}

#[derive(Debug, Serialize)]
struct ProposeRequestV1<'a> {
    policy_hash_hex: String,
    max_candidates: u32,
    state: &'a StateSnapshot,
}

#[derive(Debug, Deserialize)]
struct ProposeResponseV1 {
    candidates: Vec<CandidateInputV1>,
}

#[derive(Debug, Deserialize)]
struct CandidateInputV1 {
    action_type: String,
    #[serde(default)]
    params: HashMap<String, Value>,
    score: i64,
}

impl HttpProposer {
    pub fn new(policy_hash: PolicyHash, config: HttpProposerConfig) -> Result<Self> {
        let http = Box::new(ReqwestHttpPoster::new(config.timeout)?);
        Self::new_with_http(policy_hash, config, http)
    }

    fn new_with_http(
        policy_hash: PolicyHash,
        config: HttpProposerConfig,
        http: Box<dyn HttpPoster>,
    ) -> Result<Self> {
        validate_outbound_url(&config.base_url)?;
        if config.max_candidates == 0 || config.max_candidates > mprd_core::MAX_CANDIDATES {
            return Err(MprdError::InvalidInput(format!(
                "max_candidates out of range ({}; max {})",
                config.max_candidates,
                mprd_core::MAX_CANDIDATES
            )));
        }

        Ok(Self {
            config,
            http,
            policy_hash,
        })
    }

    fn url(&self) -> Result<String> {
        let base = self.config.base_url.trim_end_matches('/');
        let path = self.config.endpoint_path.trim_start_matches('/');
        let url = format!("{}/{}", base, path);
        validate_outbound_url(&url)?;
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakePoster {
        status: u16,
        body: &'static [u8],
    }

    impl HttpPoster for FakePoster {
        fn post_json_bytes(&self, _url: &str, _body: &[u8]) -> Result<HttpResponse> {
            Ok(HttpResponse {
                status: self.status,
                body: self.body.to_vec(),
            })
        }
    }

    #[test]
    fn rejects_non_2xx() {
        let policy_hash = Hash32([9u8; 32]);
        let config = HttpProposerConfig::default();
        let http: Box<dyn HttpPoster> = Box::new(FakePoster {
            status: 500,
            body: br#"{"candidates":[]}"#,
        });
        let proposer = HttpProposer::new_with_http(policy_hash, config, http).expect("new");
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: Hash32([0u8; 32]),
            state_ref: mprd_core::StateRef::unknown(),
        };
        let err = proposer.propose(&state).expect_err("should fail");
        assert!(err.to_string().contains("status"));
    }

    #[test]
    fn parses_candidates_and_hashes_locally() {
        let policy_hash = Hash32([9u8; 32]);
        let config = HttpProposerConfig::default();
        let http: Box<dyn HttpPoster> = Box::new(FakePoster {
            status: 200,
            body: br#"{"candidates":[{"action_type":"transfer","score":100,"params":{"amount":{"UInt":10}}}]}"#,
        });
        let proposer = HttpProposer::new_with_http(policy_hash, config, http).expect("new");
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: Hash32([0u8; 32]),
            state_ref: mprd_core::StateRef::unknown(),
        };
        let candidates = proposer.propose(&state).expect("propose ok");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].action_type, "transfer");
        assert_ne!(candidates[0].candidate_hash, Hash32([0u8; 32]));
    }

    #[test]
    fn rejects_too_many_candidates() {
        let policy_hash = Hash32([9u8; 32]);
        let mut config = HttpProposerConfig::default();
        config.max_candidates = 1;
        let http: Box<dyn HttpPoster> = Box::new(FakePoster {
            status: 200,
            body: br#"{"candidates":[{"action_type":"a","score":0,"params":{}},{"action_type":"b","score":0,"params":{}}]}"#,
        });
        let proposer = HttpProposer::new_with_http(policy_hash, config, http).expect("new");
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: Hash32([0u8; 32]),
            state_ref: mprd_core::StateRef::unknown(),
        };
        let err = proposer.propose(&state).expect_err("should reject");
        assert!(err.to_string().contains("too many candidates"));
    }
}

impl Proposer for HttpProposer {
    fn propose(&self, state: &StateSnapshot) -> Result<Vec<CandidateAction>> {
        let url = self.url()?;
        let req = ProposeRequestV1 {
            policy_hash_hex: hex::encode(self.policy_hash.0),
            max_candidates: self.config.max_candidates as u32,
            state,
        };

        let req_bytes = serde_json::to_vec(&req).map_err(|e| {
            MprdError::ExecutionError(format!("Failed to serialize proposer request: {}", e))
        })?;
        let response = self.http.post_json_bytes(&url, &req_bytes)?;
        if !(200..=299).contains(&response.status) {
            return Err(MprdError::ExecutionError(format!(
                "HTTP proposer returned status {}",
                response.status
            )));
        }

        let parsed: ProposeResponseV1 = serde_json::from_slice(&response.body)
            .map_err(|e| MprdError::ExecutionError(format!("Invalid proposer JSON: {}", e)))?;

        if parsed.candidates.len() > self.config.max_candidates {
            return Err(MprdError::BoundedValueExceeded(format!(
                "proposer returned too many candidates ({} > {})",
                parsed.candidates.len(),
                self.config.max_candidates
            )));
        }

        let mut out: Vec<CandidateAction> = Vec::with_capacity(parsed.candidates.len());
        for c in parsed.candidates {
            let mut candidate = CandidateAction {
                action_type: c.action_type,
                params: c.params,
                score: Score(c.score),
                candidate_hash: Hash32([0u8; 32]),
            };
            // Treat the proposer as untrusted: recompute candidate_hash locally.
            candidate.candidate_hash = hash_candidate(&candidate);

            // Validate candidate against schema (CBC: fail-closed on invalid)
            validate_candidate_action_v1(&candidate)?;

            out.push(candidate);
        }
        Ok(out)
    }
}
