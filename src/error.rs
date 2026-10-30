use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound,
    /// 409 with an arbitrary JSON body (e.g. the current head version).
    Conflict(serde_json::Value),
    TooLarge(String),
    TooManyRequests(String),
    Internal(String),
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn bad(m: impl Into<String>) -> Self {
        ApiError::BadRequest(m.into())
    }
    pub fn conflict(m: &str) -> Self {
        ApiError::Conflict(json!({ "error": m }))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, json!({ "error": m })),
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, json!({ "error": m })),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, json!({ "error": m })),
            ApiError::NotFound => (StatusCode::NOT_FOUND, json!({ "error": "not found" })),
            ApiError::Conflict(v) => (StatusCode::CONFLICT, v),
            ApiError::TooLarge(m) => (StatusCode::PAYLOAD_TOO_LARGE, json!({ "error": m })),
            ApiError::TooManyRequests(m) => (StatusCode::TOO_MANY_REQUESTS, json!({ "error": m })),
            ApiError::Internal(m) => {
                tracing::error!("internal error: {m}");
                (StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": "internal error" }))
            }
        };
        (status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(d) = &e {
            if d.is_unique_violation() {
                return ApiError::conflict("already exists");
            }
            if d.is_foreign_key_violation() {
                return ApiError::bad("referenced object does not exist");
            }
        }
        ApiError::Internal(e.to_string())
    }
}

impl From<object_store::Error> for ApiError {
    fn from(e: object_store::Error) -> Self {
        match e {
            object_store::Error::NotFound { .. } => ApiError::NotFound,
            e => ApiError::Internal(format!("blob store: {e}")),
        }
    }
}
