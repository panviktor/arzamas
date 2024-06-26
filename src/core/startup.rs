use crate::application::services::service_container::ServiceContainer;
use crate::user_interface::web::api::configure_documentation_services;
use crate::user_interface::web::handlers::{auth, general_handlers, notes, user};
use actix_files::Files;
use actix_web::dev::Server;
use actix_web::middleware::NormalizePath;
use actix_web::{web, App, HttpServer};
use deadpool_redis::Pool;
use lettre::AsyncSmtpTransport;
use sea_orm::DatabaseConnection;
use std::net::TcpListener;
use std::sync::Arc;
use tracing_actix_web::TracingLogger;

pub async fn run(
    listener: TcpListener,
    database: DatabaseConnection,
    redis_pool: Pool,
    email_transport: AsyncSmtpTransport<lettre::Tokio1Executor>,
) -> Result<Server, std::io::Error> {
    let redis_pool_data = web::Data::new(redis_pool.clone());
    let shared_services = Arc::new(ServiceContainer::new(
        database,
        email_transport,
        redis_pool.clone(),
    ));
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
                web::scope("/api/v1")
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
