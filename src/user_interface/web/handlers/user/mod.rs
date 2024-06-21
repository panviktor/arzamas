use crate::user_interface::web::middleware::auth::AuthCheckService;
use crate::user_interface::web::middleware::rate_limiter;
use actix_web::web;

pub mod controllers;
mod user_request_dto;
mod user_response_dto;

pub fn init_user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .wrap(AuthCheckService)
            .wrap(rate_limiter::RateLimitServices {
                requests_count: 500,
            })
            .service(web::resource("/about-me").route(web::get().to(controllers::about_me)))
            // Sessions block
            .service(web::resource("/logout").route(web::post().to(controllers::logout)))
            .service(web::resource("/logout-all").route(web::post().to(controllers::logout_all)))
            .service(
                web::resource("/current-session")
                    .route(web::get().to(controllers::current_session)),
            )
            .service(web::resource("/all-sessions").route(web::get().to(controllers::all_sessions)))
            // Reset password block
            .service(
                web::resource("/change-password")
                    .route(web::post().to(controllers::change_password)),
            )
            .service(
                web::resource("/change-email").route(web::post().to(controllers::change_email)),
            )
            .service(
                web::resource("/cancel-email-change")
                    .route(web::post().to(controllers::cancel_email_change)),
            )
            .service(
                web::resource("/confirm-email").route(web::post().to(controllers::confirm_email)),
            )
            .service(
                web::resource("/security-settings")
                    .route(web::get().to(controllers::get_security_settings))
                    .route(web::put().to(controllers::update_security_settings)),
            )
            // 2FA
            .service(
                web::scope("/2fa")
                    .service(
                        web::resource("/email/enable")
                            .route(web::post().to(controllers::enable_email_2fa)),
                    )
                    .service(
                        web::resource("/email/confirm")
                            .route(web::post().to(controllers::confirm_email_2fa)),
                    )
                    .service(
                        web::resource("/email/disable")
                            .route(web::post().to(controllers::disable_email_2fa)),
                    )
                    .service(
                        web::resource("/email/confirm-disable")
                            .route(web::post().to(controllers::confirm_disable_email_2fa)),
                    )
                    .service(
                        web::resource("/app/enable")
                            .route(web::post().to(controllers::enable_app_2fa)),
                    )
                    .service(
                        web::resource("/app/verify")
                            .route(web::post().to(controllers::verify_app_2fa)),
                    )
                    .service(
                        web::resource("/app/reset")
                            .route(web::post().to(controllers::reset_app_2fa)),
                    )
                    .service(
                        web::resource("/app/remove")
                            .route(web::post().to(controllers::remove_app_2fa)),
                    ),
            ),
    );
}
