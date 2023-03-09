use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use actix_http::body::BoxBody;
use actix_service::{Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{Error, HttpResponse};
use chrono::{Timelike, Utc};
use futures::future::{ok, Ready};

use crate::core::constants::core_constants::RATE_LIMIT_KEY_PREFIX;
use crate::core::redis::REDIS_CLIENT;
use crate::err_server;
use crate::models::ServerError;

pub struct RateLimitServices {
    pub requests_count: u64,
}

impl<S> Transform<S, ServiceRequest> for RateLimitServices
    where
        S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
        S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Transform = RateLimitMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RateLimitMiddleware {
            service: Rc::new(RefCell::new(service)),
            requests_count: self.requests_count,
        })
    }
}

pub struct RateLimitMiddleware<S> {
    service: Rc<RefCell<S>>,
    requests_count: u64
}

impl<S> Service<ServiceRequest> for RateLimitMiddleware<S>
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
        let requests_count = self.requests_count.clone();

        Box::pin(async move {
            match get_ip_addr(&req) {
                Ok(address) => {
                    match validate_session(address, requests_count).await{
                        Ok(value) => {
                            if value {
                                let ok = srv.call(req).await?;
                               return Ok(ok)
                            }
                        },
                        Err(error) => { println!("{}", error) },
                    }
                }
                Err(error) => { println!("{}", error) },
            }

            Ok(req.into_response(
                HttpResponse::TooManyRequests()
                    .finish()
            ))
        })
    }
}

pub async fn validate_session(ip_address: String, requests_count: u64) -> Result<bool, ServerError> {
    let mut redis_connection = REDIS_CLIENT.get_async_connection().await?;
    let current_minute = Utc::now().minute();
    let rate_limit_key = format!("{}:{}:{}", RATE_LIMIT_KEY_PREFIX, ip_address, current_minute);

    let (count, _): (u64, u64) = redis::pipe()
        .atomic()
        .incr(&rate_limit_key, 1)
        .expire(rate_limit_key, 60)
        .query_async(&mut redis_connection)
        .await?;

    if requests_count > count {
        return Ok(true)
    }

    return Ok(false)
}

fn get_ip_addr(req: &ServiceRequest) -> Result<String, ServerError> {
    Ok(req
        .peer_addr()
        .ok_or(err_server!("Get ip address error"))?
        .ip()
        .to_string())
}