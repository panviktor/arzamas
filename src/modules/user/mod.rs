use actix_web::{guard, web};
use crate::modules::auth::middleware;
mod controller;
mod service;

pub fn init_user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .guard(guard::Header("content-type", "application/json"))
            .wrap(middleware::AuthCheckService)

            // Sessions block
            .service(
                web::resource("/logout")
                    .route(web::post().to(controller::logout))
            )

            .service(
                web::resource("/logout-all")
                    .route(web::post().to(controller::logout_all))
            )

            .service(
                web::resource("/current-session")
                    .route(web::get().to(controller::current_session))
            )

            .service(
                web::resource("/all-sessions")
                    .route(web::get().to(controller::all_sessions))
            )

            // Reset password block
            .service(
                web::resource("/change-password")
                    .route(web::post().to(controller::change_password))
            )

            .service(
                web::resource("/change-email")
                    .route(web::post().to(controller::change_email))
            )

            .service(
                web::resource("/resend-verify-email")
                    .route(web::post().to(controller::resend_verify_email))
            )

    );
}
