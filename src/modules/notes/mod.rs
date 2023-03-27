pub mod controller;
mod service;

use actix_web::{guard, web};
use crate::core::middleware::rate_limiter;
use crate::modules::auth;

pub fn init_notes_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/notes")
            .guard(guard::Header("content-type", "application/json"))
            .wrap(auth::middleware::AuthCheckService)
            .wrap(rate_limiter::RateLimitServices { requests_count: 500 })
            .service(
                web::resource("/create")
                    .wrap(rate_limiter::RateLimitServices { requests_count: 15 })
                    .route(web::post().to(controller::create_note))
            )
            .service(
                web::resource("/get_all_notes")
                    .route(web::get().to(controller::get_all_notes))
            )
            .service(
                web::resource("/get_by_id")
                    .route(web::get().to(controller::get_by_id))
            )
            .service(
                web::resource("/delete")
                    .route(web::delete().to(controller::delete))
            )
            .service(
                web::resource("/update")
                    .wrap(rate_limiter::RateLimitServices { requests_count: 10 })
                    .route(web::put().to(controller::update))
            )
    );
}


