use crate::application::error::error::ApplicationError;
/// Module for the ServiceError struct.
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, ResponseError};
use log::error;
use serde::Serialize;
use std::fmt;
use utoipa::ToSchema;

/// A generic error for the web server.
#[derive(Debug)]
pub struct AppResponseError {
    pub code: StatusCode,
    pub path: Option<String>,
    pub message: String,
    pub show_message: bool,
}

impl AppResponseError {
    pub fn convert_to_serialized(&self) -> ServiceErrorSerialized {
        ServiceErrorSerialized {
            code: self.code.to_string(),
            path: self.path.as_deref().unwrap_or_default().to_string(),
            message: self.message.to_string(),
            show_message: self.show_message,
        }
    }
    pub fn new(
        code: StatusCode,
        path: Option<String>,
        message: String,
        show_message: bool,
    ) -> Self {
        Self {
            code,
            path,
            message,
            show_message,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceErrorSerialized {
    #[schema(default = String::default, example = "404 Not Found")]
    pub code: String,
    #[schema(default = String::default, example = "path/item")]
    pub path: String,
    #[schema(default = String::default, example = "Item not found")]
    pub message: String,
    pub show_message: bool,
}

impl AppResponseError {
    /// Shortcut for creating a 401 Unauthorized Error
    pub fn unauthorized<T: Into<String>>(req: &HttpRequest, message: T, show: bool) -> Self {
        AppResponseError {
            code: StatusCode::UNAUTHORIZED,
            path: Option::from(req.uri().path().to_string()),
            message: message.into(),
            show_message: show,
        }
    }

    /// Shortcut for creating a 500 General Server Error
    pub fn general<T: Into<String>>(req: &HttpRequest, message: T, show: bool) -> Self {
        AppResponseError {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            path: Option::from(req.uri().path().to_string()),
            message: message.into(),
            show_message: show,
        }
    }

    /// Shortcut for creating a 400 Bad Request Error
    pub fn bad_request<T: Into<String>>(req: &HttpRequest, message: T, show: bool) -> Self {
        AppResponseError {
            code: StatusCode::BAD_REQUEST,
            path: Option::from(req.uri().path().to_string()),
            message: message.into(),
            show_message: show,
        }
    }

    /// Shortcut for creating a 404 Not Found Error
    pub fn not_found<T: Into<String>>(req: &HttpRequest, message: T, show: bool) -> Self {
        AppResponseError {
            code: StatusCode::NOT_FOUND,
            path: Option::from(req.uri().path().to_string()),
            message: message.into(),
            show_message: show,
        }
    }
}

#[macro_export]
macro_rules! err_general {
    ($req:expr, $msg:expr) => {{
        log::error!("{}", $msg);
        AppResponseError::general($req, $msg, true)
    }};
}

impl fmt::Display for AppResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.code.as_str())
    }
}

//  This allows Actix to directly turn the server error
///FIXME: - remove this code after full hex refactoring ????
impl ResponseError for AppResponseError {
    fn error_response(&self) -> HttpResponse {
        error!("Path: {:?} | Message: {}", self.path, self.message);
        let status_code = self.code;
        HttpResponse::build(status_code).json(self.convert_to_serialized())
    }
}

impl ApplicationError {
    pub fn into_service_error(self, req: &HttpRequest) -> AppResponseError {
        match self {
            ApplicationError::ValidationError(msg) => {
                AppResponseError::unauthorized(req, msg, true)
            }
            ApplicationError::NotFound(msg) => AppResponseError::not_found(req, msg, true),
            ApplicationError::BadRequest(msg) => AppResponseError::bad_request(req, msg, true),
            ApplicationError::DatabaseError(msg) => AppResponseError::general(req, msg, true),
            ApplicationError::ExternalServiceError(msg) => {
                AppResponseError::general(req, msg, true)
            }
            ApplicationError::InternalServerError(msg) => AppResponseError::general(req, msg, true),
            ApplicationError::Unknown(msg) => AppResponseError::general(req, msg, true),
        }
    }
}
