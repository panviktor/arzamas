/// Module for the ServiceError struct.
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, ResponseError};
use log::error;
use sea_orm::{ConnAcquireErr, DbErr};
use serde::Serialize;
use std::fmt;
use utoipa::ToSchema;

/// A generic error for the web server.
#[derive(Debug, ToSchema)]
pub struct ServiceError {
    pub code: StatusCode,
    pub path: String,
    pub message: String,
    pub show_message: bool,
}

impl ServiceError {
    pub fn convert_to_serialized(&self) -> ServiceErrorSerialized {
        ServiceErrorSerialized {
            code: self.code.to_string(),
            path: self.path.to_string(),
            message: self.message.to_string(),
            show_message: self.show_message,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ServiceErrorSerialized {
    pub code: String,
    pub path: String,
    pub message: String,
    pub show_message: bool,
}

impl ServiceError {
    /// Shortcut for creating a 401 Unauthorized Error
    pub fn unauthorized<T: Into<String>>(req: &HttpRequest, message: T, show: bool) -> Self {
        ServiceError {
            code: StatusCode::UNAUTHORIZED,
            path: req.uri().path().to_string(),
            message: message.into(),
            show_message: show,
        }
    }

    /// Shortcut for creating a 500 General Server Error
    pub fn general<T: Into<String>>(req: &HttpRequest, message: T, show: bool) -> Self {
        ServiceError {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            path: req.uri().path().to_string(),
            message: message.into(),
            show_message: show,
        }
    }

    /// Shortcut for creating a 400 Bad Request Error
    pub fn bad_request<T: Into<String>>(req: &HttpRequest, message: T, show: bool) -> Self {
        ServiceError {
            code: StatusCode::BAD_REQUEST,
            path: req.uri().path().to_string(),
            message: message.into(),
            show_message: show,
        }
    }

    /// Shortcut for creating a 404 Not Found Error
    pub fn not_found<T: Into<String>>(req: &HttpRequest, message: T, show: bool) -> Self {
        ServiceError {
            code: StatusCode::NOT_FOUND,
            path: req.uri().path().to_string(),
            message: message.into(),
            show_message: show,
        }
    }

    /// Shortcut for creating a 429 Bad Request Error
    pub fn too_many_requests<T: Into<String>>(req: &HttpRequest, message: T, show: bool) -> Self {
        ServiceError {
            code: StatusCode::TOO_MANY_REQUESTS,
            path: req.uri().path().to_string(),
            message: message.into(),
            show_message: show,
        }
    }
}

#[macro_export]
macro_rules! err_general {
    ($req:expr, $msg:expr) => {{
        log::error!("{}", $msg);
        ServiceError::general($req, $msg, true)
    }};
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.code.as_str())
    }
}

//  This allows Actix to directly turn the server error
impl ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        error!("Path: {} | Message: {}", self.path, self.message);
        let status_code = self.code;
        HttpResponse::build(status_code).json(self.convert_to_serialized())
    }
}

impl From<DbErr> for ServiceError {
    fn from(value: DbErr) -> Self {
        let (status_code, message) = match value {
            DbErr::ConnectionAcquire(err) => match err {
                ConnAcquireErr::Timeout => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Failed to acquire a database connection due to a timeout.".to_string(),
                ),
                ConnAcquireErr::ConnectionClosed => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Failed to acquire a database connection because the connection was closed."
                        .to_string(),
                ),
            },
            DbErr::TryIntoErr { source, .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to convert value: {}", source),
            ),
            DbErr::Conn(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Database connection error: {}", e),
            ),
            DbErr::Exec(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database execution error: {}", e),
            ),
            DbErr::Query(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database query error: {}", e),
            ),
            DbErr::ConvertFromU64(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to convert from u64: {}", e),
            ),
            DbErr::UnpackInsertId => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to unpack insert ID".to_string(),
            ),
            DbErr::UpdateGetPrimaryKey => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get primary key for update".to_string(),
            ),
            DbErr::RecordNotFound(model_name) => {
                (StatusCode::NOT_FOUND, format!("{} not found", model_name))
            }
            DbErr::AttrNotSet(attr_name) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Attribute '{}' not set", attr_name),
            ),
            DbErr::Custom(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            ),
            DbErr::Type(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database type error: {}", e),
            ),
            DbErr::Json(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse JSON: {}", e),
            ),
            DbErr::Migration(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Migration error: {}", e),
            ),
            DbErr::RecordNotInserted => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to insert record".to_string(),
            ),
            DbErr::RecordNotUpdated => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to update record".to_string(),
            ),
        };

        ServiceError {
            code: status_code,
            path: "Database".to_string(),
            message,
            show_message: true,
        }
    }
}
