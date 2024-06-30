use crate::application::error::response_error::AppResponseError;
use crate::core::constants::core_constants;
use actix_http::StatusCode;
use actix_web::HttpRequest;

pub fn get_user_agent(req: &HttpRequest) -> Result<String, AppResponseError> {
    req.headers()
        .get("User-Agent")
        .ok_or_else(|| AppResponseError::bad_request(req, "User-Agent header is missing.", true))
        .and_then(|header_value| {
            header_value.to_str().map_err(|_| {
                AppResponseError::bad_request(req, "User-Agent header is not valid UTF-8.", true)
            })
        })
        .map(String::from)
}

pub fn get_ip_addr(req: &HttpRequest) -> Result<String, AppResponseError> {
    req.peer_addr()
        .map(|ip| ip.ip().to_string())
        .ok_or_else(|| {
            AppResponseError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some(req.path().to_string()),
                "Failed to retrieve IP address. IP address is unavailable.".to_string(),
                false,
            )
        })
}

pub fn extract_session_token_from_request(req: &HttpRequest) -> Result<String, AppResponseError> {
    if let Some(auth_header) = req.headers().get(core_constants::AUTHORIZATION) {
        if let Ok(auth_header_str) = auth_header.to_str() {
            if auth_header_str.starts_with(core_constants::BEARER) {
                let token = auth_header_str[core_constants::BEARER.len()..].trim();
                return Ok(token.to_string());
            }
        }
    }

    Err(AppResponseError {
        code: StatusCode::UNAUTHORIZED,
        path: Some(req.path().to_string()),
        message: "Authorization header is missing or invalid.".to_string(),
        show_message: true,
    })
}
