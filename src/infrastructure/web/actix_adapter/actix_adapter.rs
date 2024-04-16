use crate::application::error::response_error::AppResponseError;
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
    req.peer_addr().map(|ip| ip.to_string()).ok_or_else(|| {
        AppResponseError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some(req.path().to_string()),
            "Failed to retrieve IP address. IP address is unavailable.".to_string(),
            false,
        )
    })
}
