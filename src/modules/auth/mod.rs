/// Module that contains all the functions related to authentication.
use actix_web::{ web, guard};
mod controller;
mod service;

pub fn init_auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .guard(guard::Header("content-type", "application/json"))
            .service(
                web::resource("/create")
                        .route(web::post().to(controller::create_user))
            )
            .service(
                web::resource("/find")
                    .route(web::get().to(controller::find_user))
            )
    );
}



