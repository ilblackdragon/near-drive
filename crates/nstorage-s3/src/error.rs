//! S3 error responses (`<Error><Code>…</Code>…</Error>`).
use crate::xml::escape;
use axum::{
    body::Body,
    http::{header, StatusCode},
    response::Response,
};

#[derive(Debug, Clone)]
pub struct S3Error {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

pub type S3Result<T> = Result<T, S3Error>;

impl S3Error {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into() }
    }

    pub fn access_denied(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "AccessDenied", m)
    }
    pub fn signature_mismatch() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
        )
    }
    pub fn invalid_access_key() -> Self {
        Self::new(StatusCode::FORBIDDEN, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.")
    }
    pub fn skewed() -> Self {
        Self::new(StatusCode::FORBIDDEN, "RequestTimeTooSkewed", "The difference between the request time and the current time is too large.")
    }
    pub fn no_such_key() -> Self {
        Self::new(StatusCode::NOT_FOUND, "NoSuchKey", "The specified key does not exist.")
    }
    pub fn no_such_bucket() -> Self {
        Self::new(StatusCode::NOT_FOUND, "NoSuchBucket", "The specified bucket does not exist.")
    }
    pub fn no_such_upload() -> Self {
        Self::new(StatusCode::NOT_FOUND, "NoSuchUpload", "The specified multipart upload does not exist.")
    }
    pub fn invalid_argument(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "InvalidArgument", m)
    }
    pub fn invalid_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "InvalidRequest", m)
    }
    pub fn malformed_xml() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema.")
    }
    pub fn not_implemented(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_IMPLEMENTED, "NotImplemented", m)
    }
    pub fn internal(m: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", m)
    }
    pub fn bad_digest(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "BadDigest", m)
    }

    pub fn into_response(self, resource: &str, request_id: &str, head: bool) -> Response {
        let body = if head {
            Body::empty()
        } else {
            Body::from(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{}</Code><Message>{}</Message><Resource>{}</Resource><RequestId>{}</RequestId></Error>",
                self.code,
                escape(&self.message),
                escape(resource),
                request_id
            ))
        };
        Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "application/xml")
            .body(body)
            .expect("valid error response")
    }
}

impl From<std::io::Error> for S3Error {
    fn from(e: std::io::Error) -> Self {
        tracing::error!("io error: {e}");
        S3Error::internal("local I/O error")
    }
}
