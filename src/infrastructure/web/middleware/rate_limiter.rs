use crate::core::constants::core_constants::RATE_LIMIT_KEY_PREFIX;
use actix_http::body::BoxBody;
use actix_service::{Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{web, Error, HttpResponse};
use chrono::{Timelike, Utc};
use deadpool_redis::Pool;
use futures::future::{ok, Ready};
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use crate::infrastructure::error::error::InfrastructureError;

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
    requests_count: u64,
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
        let requests_count = self.requests_count;

        Box::pin(async move {
            let redis_pool = match req.app_data::<web::Data<Pool>>() {
                Some(pool) => pool,
                None => {
                    return Ok(req.into_response(
                        HttpResponse::InternalServerError()
                            .json("RateLimit Redis pool not found!!"),
                    ));
                }
            };

            // Handle IP address retrieval and validate the session
            match get_ip_addr(&req) {
                Ok(address) => {
                    match validate_session(address, requests_count, redis_pool.get_ref()).await {
                        Ok(true) => srv.call(req).await,
                        Ok(false) => {
                            // If the session is not valid, respond with Too Many Requests
                            Ok(req.into_response(HttpResponse::TooManyRequests().finish()))
                        }
                        Err(error) => {
                            eprintln!("Session validation error: {:?}", error);
                            Ok(req.into_response(HttpResponse::InternalServerError().finish()))
                        }
                    }
                }
                Err(error) => {
                    // Log the IP address retrieval error and respond with Internal Server Error
                    eprintln!("IP address retrieval error: {:?}", error);
                    Ok(req.into_response(HttpResponse::InternalServerError().finish()))
                }
            }
        })
    }
}

async fn validate_session(
    ip_address: String,
    requests_count: u64,
    pool: &Pool,
) -> Result<bool, InfrastructureError> {
    let mut conn = pool.get().await.map_err(|_| {
        InfrastructureError::NetworkError("Failed to get Redis connection".to_string())
    })?;

    let current_minute = Utc::now().minute();
    let rate_limit_key = format!(
        "{}:{}:{}",
        RATE_LIMIT_KEY_PREFIX, ip_address, current_minute
    );

    let results: (u64, bool) = redis::pipe()
        .atomic()
        .incr(&rate_limit_key, 1)
        .expire(&rate_limit_key, 60)
        .query_async::<_, (u64, bool)>(&mut conn)
        .await
        .map_err(|e| InfrastructureError::NetworkError(format!("Redis error: {}", e)))?;

    if results.0 > requests_count {
        Ok(false)
    } else {
        Ok(true)
    }
}

fn get_ip_addr(req: &ServiceRequest) -> Result<String, InfrastructureError> {
    req.peer_addr()
        .ok_or(InfrastructureError::NetworkError(
            "Get IP address error".to_string(),
        ))
        .map(|addr| addr.ip().to_string())
}
