use lib::core::config::get_config;
use lib::core::startup::run;
// use lib::application::telemetry::{get_subscriber, init_subscriber};
use lib::infrastructure::persistence::db::{check_migration, create_db_pool};
// use std::env;
use lib::infrastructure::cache::redis::create_redis_pool;

use lib::infrastructure::email::lettre_email_adapter::create_mail_transport;
use std::net::TcpListener;

// const APPLICATION_NAME: &str = "Arzamas";

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    // let application_telemetry_path = env::var("APPLICATION_TELEMETRY_PATH").unwrap_or_else(|_| "".to_string());

    // match application_telemetry_path {
    //     application_telemetry_path if application_telemetry_path != "" => {
    //         // Set up a subscriber for logging to files, rolling daily
    //         let subscriber = get_subscriber(
    //             APPLICATION_NAME.to_owned(),
    //             "info".to_string(),
    //             tracing_appender::rolling::daily(application_telemetry_path, "log"),
    //         );
    //         init_subscriber(subscriber);
    //     }
    //     _ => {
    //         // Set up a subscriber for logging to the terminal -- good for development
    //         let subscriber = get_subscriber(
    //             APPLICATION_NAME.to_owned(),
    //             "info".to_string(),
    //             std::io::stdout,
    //         );
    //         init_subscriber(subscriber);
    //     }
    // }

    // Read the configuration from the environment.
    let config = get_config().expect("Failed to read configuration.");

    // Create a TCP listener at the configured address.
    let address = format!("0.0.0.0:{}", config.application_port);
    println!("{}", address);
    let listener = TcpListener::bind(address)?;

    let connection = create_db_pool().await;
    check_migration(&connection).await;

    let redis_pool = create_redis_pool().expect("Cannot create deadpool redis.");

    let email_transport = create_mail_transport();

    // Run the App 🚀
    match run(listener, connection, redis_pool, email_transport).await {
        Ok(server) => {
            // If the server is successfully created, run it
            server.await
        }
        Err(e) => {
            // Handle any errors that occurred during server creation
            println!("Failed to start the server: {}", e);
            Err(e)
        }
    }
}
