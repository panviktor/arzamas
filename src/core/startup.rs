use actix_web::{middleware, web, App, HttpServer};
use actix_files::Files;
use actix_web::dev::Server;
use std::net::TcpListener;

use tracing_actix_web::TracingLogger;
use crate::modules::general_handlers;
use crate::modules::auth;
use crate::core::db::DB;

pub async fn run(listener: TcpListener) -> Result<Server, std::io::Error> {

    let db = web::Data::new(&*DB);

    let server = HttpServer::new(move || {
        App::new()
            // Removes trailing slash in the URL to make is so I don't need as many services
            .wrap(middleware::NormalizePath::trim())
            .wrap(TracingLogger::default())
            // Register your controllers below 👇
            .service(Files::new("/.well-known", ".well-known/"))
            // Register your general_handlers routes
            .configure(general_handlers::init_general_handlers_routes)
            // Register your auth routes
            .service(
                web::scope("/api")
                    .configure(auth::init_auth_routes)
            )
            .default_service(web::route().to(general_handlers::p404))
            // Register application-wide models data below 👇
            .app_data(db.clone()) // 👈 ❗Important: Register the database connection pool
    })
        .listen(listener)?
        .run();
    Ok(server)
}

