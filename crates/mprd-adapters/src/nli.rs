use mprd_core::hash::hash_candidate;
use mprd_core::validation::{
    validate_action_schema_v1, validate_candidate_action_v1, ACTION_TYPE_HTTP_CALL_V1,
    ACTION_TYPE_NOOP_V1,
};
use mprd_core::{CandidateAction, MprdError, Proposer, Result, Score, StateSnapshot, Value};
use std::collections::HashMap;

pub const OPERATOR_COMMAND_FIELD_V1: &str = "mprd.nli.operator_command_v1";

#[derive(Debug, Clone)]
pub struct LocalNliProposerConfig {
    pub max_candidates: usize,
}

impl Default for LocalNliProposerConfig {
    fn default() -> Self {
        Self {
            max_candidates: mprd_core::MAX_CANDIDATES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalNliProposer {
    config: LocalNliProposerConfig,
}

impl LocalNliProposer {
    pub fn new(config: LocalNliProposerConfig) -> Result<Self> {
        if config.max_candidates == 0 || config.max_candidates > mprd_core::MAX_CANDIDATES {
            return Err(MprdError::ConfigError(format!(
                "max_candidates out of range ({}; max {})",
                config.max_candidates,
                mprd_core::MAX_CANDIDATES
            )));
        }
        Ok(Self { config })
    }
}

impl Proposer for LocalNliProposer {
    fn propose(&self, state: &StateSnapshot) -> Result<Vec<CandidateAction>> {
        let command = match state.fields.get(OPERATOR_COMMAND_FIELD_V1) {
            Some(Value::String(s)) => normalize_operator_command_v1(s),
            _ => String::new(),
        };

        let parsed_candidate = parse_command_v1(&command).and_then(|cmd| {
            candidate_from_parsed_command(cmd, Score(100))
                .ok()
                .and_then(|c| finalize_candidate_v1(c).ok())
        });

        let mut out: Vec<CandidateAction> = Vec::new();
        if let Some(c) = parsed_candidate {
            out.push(c);
        }

        if out.is_empty() {
            out.push(finalize_candidate_v1(noop_candidate(Score(0)))?);
            return Ok(out);
        }

        if out.len() < self.config.max_candidates && out[0].action_type != ACTION_TYPE_NOOP_V1 {
            out.push(finalize_candidate_v1(noop_candidate(Score(0)))?);
        }

        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedCommandV1 {
    Noop,
    HttpCall(ParsedHttpCallV1),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedHttpCallV1 {
    method: String,
    url: String,
    expected_status: Option<u16>,
    content_type: Option<String>,
    body_utf8: Option<String>,
    implied_json_content_type: bool,
}

fn normalize_operator_command_v1(s: &str) -> String {
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    s.trim().to_string()
}

fn parse_command_v1(command: &str) -> Option<ParsedCommandV1> {
    if command.is_empty() {
        return None;
    }

    if is_noop_command_v1(command) {
        return Some(ParsedCommandV1::Noop);
    }

    parse_http_call_command_v1(command)
        .ok()
        .map(ParsedCommandV1::HttpCall)
}

fn is_noop_command_v1(command: &str) -> bool {
    let c = command.trim();
    c.eq_ignore_ascii_case("noop")
        || c.eq_ignore_ascii_case("no-op")
        || c.eq_ignore_ascii_case("no op")
        || c.eq_ignore_ascii_case("do nothing")
        || c.eq_ignore_ascii_case("skip")
        || c.eq_ignore_ascii_case("cancel")
        || c.eq_ignore_ascii_case("abort")
}

fn candidate_from_parsed_command(
    cmd: ParsedCommandV1,
    score: Score,
) -> std::result::Result<CandidateAction, ()> {
    match cmd {
        ParsedCommandV1::Noop => Ok(noop_candidate(score)),
        ParsedCommandV1::HttpCall(parsed) => http_call_candidate(parsed, score),
    }
}

fn noop_candidate(score: Score) -> CandidateAction {
    CandidateAction {
        action_type: ACTION_TYPE_NOOP_V1.to_string(),
        params: HashMap::new(),
        score,
        candidate_hash: mprd_core::Hash32([0u8; 32]),
    }
}

fn http_call_candidate(
    parsed: ParsedHttpCallV1,
    score: Score,
) -> std::result::Result<CandidateAction, ()> {
    let mut params: HashMap<String, Value> = HashMap::new();
    params.insert("http_method".into(), Value::String(parsed.method));
    params.insert("http_url".into(), Value::String(parsed.url));
    if let Some(status) = parsed.expected_status {
        params.insert("http_expected_status".into(), Value::UInt(status as u64));
    }
    if let Some(ct) = parsed.content_type {
        params.insert("http_content_type".into(), Value::String(ct));
    }
    if let Some(body) = parsed.body_utf8 {
        params.insert("http_body".into(), Value::Bytes(body.into_bytes()));
    }
    if parsed.implied_json_content_type && !params.contains_key("http_content_type") {
        params.insert(
            "http_content_type".into(),
            Value::String("application/json".into()),
        );
    }

    Ok(CandidateAction {
        action_type: ACTION_TYPE_HTTP_CALL_V1.to_string(),
        params,
        score,
        candidate_hash: mprd_core::Hash32([0u8; 32]),
    })
}

fn finalize_candidate_v1(mut candidate: CandidateAction) -> Result<CandidateAction> {
    validate_candidate_action_v1(&candidate)?;
    validate_action_schema_v1(&candidate.action_type, &candidate.params)?;
    candidate.candidate_hash = hash_candidate(&candidate);
    Ok(candidate)
}

fn parse_http_call_command_v1(command: &str) -> Result<ParsedHttpCallV1> {
    let (rest, parsed) = http_call_grammar::http_call(command).map_err(|e| {
        MprdError::InvalidInput(format!("failed to parse http_call command: {:?}", e))
    })?;
    if !rest.trim().is_empty() {
        return Err(MprdError::InvalidInput(
            "failed to parse http_call command: trailing content".into(),
        ));
    }
    Ok(parsed)
}

mod http_call_grammar {
    use super::ParsedHttpCallV1;
    use nom::branch::alt;
    use nom::bytes::complete::{tag, tag_no_case, take_while1};
    use nom::character::complete::{multispace1, one_of};
    use nom::combinator::{map, opt};
    use nom::sequence::{preceded, terminated, tuple};
    use nom::IResult;

    pub fn http_call(input: &str) -> IResult<&str, ParsedHttpCallV1> {
        let (input, method) = method(input)?;
        let (input, _) = multispace1(input)?;
        let (input, url) = token(input)?;

        let (input, expected_status) = opt(preceded(multispace1, expect_clause))(input)?;
        let (input, content_type) = opt(preceded(multispace1, content_type_clause))(input)?;
        let (input, body_clause) = opt(preceded(multispace1, body_clause))(input)?;

        let (body_utf8, implied_json_content_type) = match body_clause {
            Some(BodyClause::Body(s)) => (Some(s), false),
            Some(BodyClause::WithJson(s)) => (Some(s), true),
            None => (None, false),
        };

        Ok((
            input,
            ParsedHttpCallV1 {
                method,
                url,
                expected_status,
                content_type,
                body_utf8,
                implied_json_content_type,
            },
        ))
    }

    fn method(input: &str) -> IResult<&str, String> {
        map(
            alt((
                tag_no_case("GET"),
                tag_no_case("POST"),
                tag_no_case("PUT"),
                tag_no_case("PATCH"),
                tag_no_case("DELETE"),
            )),
            |s: &str| s.to_ascii_uppercase(),
        )(input)
    }

    fn token(input: &str) -> IResult<&str, String> {
        map(take_while1(|c: char| !c.is_whitespace()), |s: &str| {
            s.to_string()
        })(input)
    }

    fn status(input: &str) -> IResult<&str, u16> {
        let (rest, (a, b, c)) =
            tuple((one_of("12345"), one_of("0123456789"), one_of("0123456789")))(input)?;
        let status = ((a as u16 - b'0' as u16) * 100)
            + ((b as u16 - b'0' as u16) * 10)
            + (c as u16 - b'0' as u16);
        Ok((rest, status))
    }

    fn expect_clause(input: &str) -> IResult<&str, u16> {
        let (input, _) = tag_no_case("expect")(input)?;
        let (input, _) = multispace1(input)?;
        status(input)
    }

    fn content_type_clause(input: &str) -> IResult<&str, String> {
        let (input, _) = tag_no_case("content-type")(input)?;
        let (input, _) = multispace1(input)?;
        atom(input)
    }

    enum BodyClause {
        Body(String),
        WithJson(String),
    }

    fn body_clause(input: &str) -> IResult<&str, BodyClause> {
        alt((
            map(
                tuple((tag_no_case("body"), multispace1, atom)),
                |(_, _, body)| BodyClause::Body(body),
            ),
            map(
                tuple((
                    tag_no_case("with"),
                    multispace1,
                    tag_no_case("json"),
                    multispace1,
                    atom,
                )),
                |(_, _, _, _, body)| BodyClause::WithJson(body),
            ),
        ))(input)
    }

    fn atom(input: &str) -> IResult<&str, String> {
        alt((single_quoted, double_quoted, token))(input)
    }

    fn single_quoted(input: &str) -> IResult<&str, String> {
        let (input, _) = tag("'")(input)?;
        let (input, s) = terminated(take_while1(|c| c != '\''), tag("'"))(input)?;
        Ok((input, s.to_string()))
    }

    fn double_quoted(input: &str) -> IResult<&str, String> {
        let (rest, raw) = recognize_json_string(input)?;
        let parsed: String = serde_json::from_str(raw).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Escaped,
            ))
        })?;
        if parsed.is_empty() {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::LengthValue,
            )));
        }
        Ok((rest, parsed))
    }

    fn recognize_json_string(input: &str) -> IResult<&str, &str> {
        nom::combinator::recognize(tuple((
            tag("\""),
            opt(nom::bytes::complete::escaped(
                nom::bytes::complete::is_not("\\\""),
                '\\',
                alt((
                    tag("\\"),
                    tag("\""),
                    tag("/"),
                    tag("b"),
                    tag("f"),
                    tag("n"),
                    tag("r"),
                    tag("t"),
                    nom::combinator::recognize(tuple((
                        tag("u"),
                        nom::bytes::complete::take(4usize),
                    ))),
                )),
            )),
            tag("\""),
        )))(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_http_call() {
        let parsed = parse_http_call_command_v1("GET https://example.com/health").expect("parse");
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.url, "https://example.com/health");
        assert_eq!(parsed.expected_status, None);
        assert_eq!(parsed.content_type, None);
        assert_eq!(parsed.body_utf8, None);
    }

    #[test]
    fn parses_expect_status() {
        let parsed =
            parse_http_call_command_v1("GET https://example.com expect 204").expect("parse");
        assert_eq!(parsed.expected_status, Some(204));
    }

    #[test]
    fn parses_content_type() {
        let parsed =
            parse_http_call_command_v1("POST https://example.com content-type application/json")
                .expect("parse");
        assert_eq!(parsed.content_type, Some("application/json".into()));
    }

    #[test]
    fn parses_body_token() {
        let parsed =
            parse_http_call_command_v1("POST https://example.com body {\"a\":1}").expect("parse");
        assert_eq!(parsed.body_utf8, Some("{\"a\":1}".into()));
    }

    #[test]
    fn parses_body_single_quoted() {
        let parsed = parse_http_call_command_v1("POST https://example.com body '{\"a\": 1}'")
            .expect("parse");
        assert_eq!(parsed.body_utf8, Some("{\"a\": 1}".into()));
    }

    #[test]
    fn parses_with_json_alias_and_implies_content_type() {
        let parsed = parse_http_call_command_v1("POST https://example.com with JSON {\"a\":1}")
            .expect("parse");
        assert_eq!(parsed.body_utf8, Some("{\"a\":1}".into()));
        assert!(parsed.implied_json_content_type);
        let c = http_call_candidate(parsed, Score(100)).expect("candidate");
        assert_eq!(
            c.params.get("http_content_type"),
            Some(&Value::String("application/json".into()))
        );
    }

    #[test]
    fn rejects_trailing_content_after_body_token() {
        let err = parse_http_call_command_v1("POST https://example.com body hi expect 200")
            .expect_err("should reject");
        assert!(err.to_string().contains("trailing"));
    }
}
