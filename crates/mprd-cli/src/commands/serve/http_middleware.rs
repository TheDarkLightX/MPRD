use axum::body::Body;
use axum::http::{header, Method, StatusCode};
use axum::{middleware, response::Response};

pub(super) async fn cors_middleware(
    req: axum::http::Request<Body>,
    next: middleware::Next,
) -> Response {
    if req.method() == Method::OPTIONS {
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::NO_CONTENT;
        let headers = resp.headers_mut();
        headers.insert(
            "Access-Control-Allow-Origin",
            header::HeaderValue::from_static("*"),
        );
        headers.insert(
            "Access-Control-Allow-Methods",
            header::HeaderValue::from_static("GET,POST,OPTIONS"),
        );
        headers.insert(
            "Access-Control-Allow-Headers",
            header::HeaderValue::from_static("Content-Type,X-API-Key"),
        );
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            header::HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            header::X_FRAME_OPTIONS,
            header::HeaderValue::from_static("DENY"),
        );
        headers.insert(
            header::REFERRER_POLICY,
            header::HeaderValue::from_static("no-referrer"),
        );
        headers.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        return resp;
    }

    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        "Access-Control-Allow-Origin",
        header::HeaderValue::from_static("*"),
    );
    headers.insert(
        "Access-Control-Allow-Methods",
        header::HeaderValue::from_static("GET,POST,OPTIONS"),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        header::HeaderValue::from_static("Content-Type,X-API-Key"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    resp
}
