use std::borrow::Borrow;
use lib::core::config::get_config;
use lib::core::startup::run;
use lib::core::telemetry::{get_subscriber, init_subscriber};
use lib::core::db::init_db;
use std::env;
use std::net::TcpListener;

const APPLICATION_NAME: &str = "Arzamas";

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let application_telemetry_path = env::var("APPLICATION_TELEMETRY_PATH").unwrap_or_else(|_| "".to_string());


    match application_telemetry_path {
        application_telemetry_path if application_telemetry_path != "" => {
            // Set up a subscriber for logging to files, rolling daily
            let subscriber = get_subscriber(
                APPLICATION_NAME.to_owned(),
                "info".to_string(),
                tracing_appender::rolling::daily(application_telemetry_path, "log"),
            );
            init_subscriber(subscriber);
        }
        _ => {
            // Set up a subscriber for logging to the terminal -- good for development
            let subscriber = get_subscriber(
                APPLICATION_NAME.to_owned(),
                "info".to_string(),
                std::io::stdout,
            );
            init_subscriber(subscriber);
        }
    }

    // Read the configuration from the environment.
    let config = get_config().expect("Failed to read configuration.");



    // Create a TCP listener at the configured address.
    let address = format!("127.0.0.1:{}", config.application_port);
    println!("{}", address);
    let listener = TcpListener::bind(address)?;

    // Run the App 🚀

    init_db().await;
    run(listener).await?.await
}
