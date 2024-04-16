use crate::infrastructure::web::middleware::rate_limiter;
use actix_web::web;
mod auth_request_dto;
mod auth_response_dto;
pub mod controllers;

pub fn init_auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .wrap(rate_limiter::RateLimitServices {
                requests_count: 200,
            })
            .service(
                web::resource("/create")
                    .wrap(rate_limiter::RateLimitServices {
                        requests_count: 100,
                    })
                    .route(web::post().to(controllers::create_user)),
            )
            .service(
                web::resource("/verify-email")
                    .wrap(rate_limiter::RateLimitServices {
                        requests_count: 100,
                    })
                    .route(web::post().to(controllers::verify_email)),
            )
            .service(
                web::resource("/login")
                    .wrap(rate_limiter::RateLimitServices { requests_count: 50 })
                    .route(web::post().to(controllers::login)),
            )
            .service(
                web::resource("/forgot-password")
                    .wrap(rate_limiter::RateLimitServices { requests_count: 25 })
                    .route(web::post().to(controllers::forgot_password)),
            )
            .service(
                web::resource("/password-reset")
                    .wrap(rate_limiter::RateLimitServices { requests_count: 25 })
                    .route(web::post().to(controllers::password_reset)),
            )
            .service(
                web::resource("/login-2fa")
                    .wrap(rate_limiter::RateLimitServices { requests_count: 50 })
                    .route(web::post().to(controllers::login_2fa)),
            ),
    );
}
