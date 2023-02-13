/// Module that contains all the auth middleware.
use crate::modules::auth::session::{get_session_token_service_request, validate_session};

use actix_http::body::BoxBody;
use actix_service::{Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{Error, HttpResponse};
use futures::future::{ok, Ready};
use futures::Future;
use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use tracing::error;

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
            let is_logged_in = match get_session_token_service_request(&req) {
                Some(token) => {
                    match validate_session(&token).await {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Error validating token: {}", e);
                            false
                        }
                    }
                }
                None => false
            };

            if is_logged_in {
                let ok = srv.call(req).await?;
                Ok(ok)
            } else {
                Ok(req.into_response(
                    HttpResponse::Unauthorized()
                        .finish()
                ))
            }
        })
    }
}