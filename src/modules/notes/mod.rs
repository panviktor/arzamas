pub mod controller;
use actix_web::{guard, web};
use crate::modules::auth::middleware;

pub fn init_notes_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/notes")
            .wrap(middleware::AuthCheckService)
            .guard(guard::Header("content-type", "application/json"))
            .service(
                web::resource("/create")
                    .route(web::post().to(controller::create_note))
            )
            .service(
                web::resource("/get_all_notes")
                    .route(web::get().to(controller::get_all_notes))
            )
    );
}


