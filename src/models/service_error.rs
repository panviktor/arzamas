/// Module for the ServiceError struct.

use actix_web::http::{StatusCode};
use actix_web::{HttpRequest, HttpResponse, ResponseError};
use std::fmt;
use log::error;
use serde::Serialize;

/// A generic error for the web server.
#[derive(Debug)]
pub struct ServiceError {
    pub code: StatusCode,
    pub path: String,
    pub message: String,
    pub show_message: bool
}

impl ServiceError {
    pub fn convert_to_serialized(&self) -> ServiceErrorSerialized {
        ServiceErrorSerialized {
            code: self.code.to_string(),
            path: self.path.to_string(),
            message: self.message.to_string(),
            show_message: self.show_message
        }
    }
}

#[derive(Debug)]
#[derive(Serialize)]
pub struct ServiceErrorSerialized {
    pub code: String,
    pub path: String,
    pub message: String,
    pub show_message: bool
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

impl From<sea_orm::DbErr> for ServiceError {
    fn from(value: sea_orm::DbErr) -> Self {
        ServiceError {
            code: StatusCode::SERVICE_UNAVAILABLE,
            path: "DB".to_string(),
            message: "DB ERROR".to_string(),
            show_message: true,
        }
    }
}