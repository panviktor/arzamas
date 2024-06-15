pub mod controllers;
pub mod note_request_dto;
use crate::user_interface::web::middleware::auth::AuthCheckService;
use crate::user_interface::web::middleware::rate_limiter;
use actix_web::web;

pub fn init_notes_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/note")
            .wrap(AuthCheckService)
            .wrap(rate_limiter::RateLimitServices {
                requests_count: 500,
            })
            .service(
                web::resource("/create")
                    .wrap(rate_limiter::RateLimitServices { requests_count: 15 })
                    .route(web::post().to(controllers::create_note)),
            )
            .service(
                web::resource("/get_all_notes").route(web::get().to(controllers::get_all_notes)),
            )
            .service(web::resource("/get_by_id").route(web::get().to(controllers::get_by_id)))
            .service(web::resource("/delete").route(web::delete().to(controllers::delete)))
            .service(
                web::resource("/update")
                    .wrap(rate_limiter::RateLimitServices { requests_count: 10 })
                    .route(web::put().to(controllers::update)),
            ),
    );
}
