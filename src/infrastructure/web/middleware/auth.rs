// use crate::modules_deprecated::auth::session::{
//     get_session_token_service_request, validate_session,
// };
/// Module that contains all the auth middleware.
use actix_http::body::BoxBody;
use actix_http::HttpMessage;
use actix_service::{Service, Transform};
use actix_web::{
    dev,
    dev::{ServiceRequest, ServiceResponse},
    web, Error, FromRequest, HttpRequest, HttpResponse,
};
use deadpool_redis::Pool;
use futures::future::{err, ok, Ready};
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
            //     let redis_pool = match req.app_data::<web::Data<Pool>>() {
            //         Some(pool) => pool,
            //         None => {
            //             return Ok(req.into_response(
            //                 HttpResponse::InternalServerError().json("Auth Redis pool not found!"),
            //             ));
            //         }
            //     };
            //
            //     let is_logged_in = match get_session_token_service_request(&req) {
            //         Some(token) => validate_session(&token, redis_pool)
            //             .await
            //             .unwrap_or_else(|e| {
            //                 error!("Error validating token: {}", e);
            //                 None
            //             }),
            //         None => None,
            //     };
            //
            //     match is_logged_in {
            //         Some(user_id) => {
            //             let user = LoginUser { id: user_id };
            //             req.extensions_mut().insert(user);
            //             let ok = srv.call(req).await?;
            //             Ok(ok)
            //         }
            //         None => Ok(req.into_response(HttpResponse::Unauthorized().finish())),
            //     }
            todo!()
        })
    }
}

#[derive(Debug, Clone)]
pub struct LoginUser {
    pub(crate) id: String,
}
impl FromRequest for LoginUser {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
        return match req.extensions().get::<LoginUser>() {
            Some(user) => ok(user.clone()),
            None => err(actix_web::error::ErrorBadRequest("ups...")),
        };
    }
}
