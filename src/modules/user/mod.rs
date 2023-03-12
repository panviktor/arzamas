use actix_web::{guard, web};
use crate::modules::auth::middleware;

pub mod controller;

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
    );
}
