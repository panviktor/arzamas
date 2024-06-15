use actix_http::body::BoxBody;
use actix_http::HttpMessage;
use actix_service::{Service, Transform};
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    web, Error, HttpResponse,
};

use crate::application::services::service_container::ServiceContainer;
use crate::core::constants::core_constants;
use crate::infrastructure::error::error::InfrastructureError;
use crate::user_interface::web::dto::shared::LoginUser;
use actix_http::header::HeaderValue;
use futures::future::{ok, Ready};
use futures::Future;
use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Wrapper for checking that the user is logged in
/// Checks that there is a valid session cookie sent along with the request.
#[derive(Clone)]
pub struct AuthCheckService;

impl<S> Transform<S, ServiceRequest> for AuthCheckService
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Transform = AuthCheckMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthCheckMiddleware {
            service: Rc::new(RefCell::new(service)),
        })
    }
}

pub struct AuthCheckMiddleware<S> {
    service: Rc<RefCell<S>>,
}

impl<S> Service<ServiceRequest> for AuthCheckMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = self.service.clone();
        // Run this async so we can use async functions.
        Box::pin(async move {
            let data = match req.app_data::<web::Data<Arc<ServiceContainer>>>() {
                Some(data) => data,
                None => {
                    return Ok(req.into_response(
                        HttpResponse::InternalServerError().json("Service container not found"),
                    ));
                }
            };

            match get_session_token_service_request(&req) {
                Ok(token) => {
                    match data
                        .user_authentication_service
                        .validate_session_for_user(&token)
                        .await
                    {
                        Ok(user_id) => {
                            let user = LoginUser { id: user_id };
                            req.extensions_mut().insert(user);
                            srv.call(req).await
                        }
                        Err(e) => {
                            Ok(req.into_response(HttpResponse::InternalServerError().json(e)))
                        }
                    }
                }
                Err(e) => Ok(req.into_response(HttpResponse::InternalServerError().json(e))),
            }
        })
    }
}

fn get_session_token_service_request(req: &ServiceRequest) -> Result<String, InfrastructureError> {
    req.headers()
        .get(core_constants::AUTHORIZATION)
        .ok_or(InfrastructureError::NetworkError(
            "Authorization header not found".to_string(),
        ))
        .and_then(|header| extract_token(header))
}
fn extract_token(authed_header: &HeaderValue) -> Result<String, InfrastructureError> {
    authed_header
        .to_str()
        .map_err(|_| InfrastructureError::NetworkError("Invalid token format".to_string()))
        .and_then(|header_str| {
            if header_str.starts_with(core_constants::BEARER) {
                let token = &header_str[core_constants::BEARER.len()..].trim();
                if token.is_empty() {
                    Err(InfrastructureError::NetworkError(
                        "Token is empty".to_string(),
                    ))
                } else {
                    Ok(token.to_string())
                }
            } else {
                Err(InfrastructureError::NetworkError(
                    "Bearer prefix not found".to_string(),
                ))
            }
        })
}
