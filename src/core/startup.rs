use crate::application::services::service_container::ServiceContainer;
use crate::infrastructure::web::api::configure_documentation_services;
use crate::infrastructure::web::handlers::{auth, general_handlers, notes, user};
use actix_files::Files;
use actix_web::dev::Server;
use actix_web::middleware::NormalizePath;
use actix_web::{web, App, HttpServer};
use deadpool_redis::Pool;
use sea_orm::DatabaseConnection;
use std::net::TcpListener;
use std::sync::Arc;
use tracing_actix_web::TracingLogger;

pub async fn run(
    listener: TcpListener,
    database: DatabaseConnection,
    redis_pool: Pool,
) -> Result<Server, std::io::Error> {
    std::env::set_var("RUST_LOG", "actix_web=debug");
    env_logger::init();

    let redis_pool_data = web::Data::new(redis_pool);
    let shared_services = Arc::new(ServiceContainer::new(database));
    let data_container = web::Data::new(shared_services);

    let server = HttpServer::new(move || {
        App::new()
            .wrap(NormalizePath::trim())
            .wrap(TracingLogger::default())
            // Register your controllers below 👇
            .service(Files::new("/.well-known", ".well-known/"))
            // Register your general_handlers routes
            .configure(general_handlers::init_general_handlers_routes)
            // Register your auth routes
            .service(
                web::scope("/api")
                    .configure(auth::init_auth_routes)
                    .configure(notes::init_notes_routes)
                    .configure(user::init_user_routes),
            )
            .default_service(web::route().to(general_handlers::p404))
            // Register application-wide models data below 👇
            .service(configure_documentation_services())
            //  Register the database connection pool
            .app_data(redis_pool_data.clone())
            .app_data(data_container.clone())
    })
    .listen(listener)?
    .run();
    Ok(server)
}
