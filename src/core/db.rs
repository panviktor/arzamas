use std::env;
use lazy_static::lazy_static;
use sea_orm::{ ConnectOptions, Database, DbConn, DbErr};
use sea_orm::DatabaseConnection;
use secrecy::ExposeSecret;
use tracing::debug;
use migration::{Migrator, MigratorTrait};

use crate::core::config::get_config;

lazy_static! {
    pub static ref DB: DatabaseConnection = {
        async_std::task::block_on(async {
            let config = get_config().expect("Failed to read configuration.");
            let opt = ConnectOptions::new(config.database.connection_string().expose_secret().to_string());
            Database::connect(opt).await.unwrap()
        })
    };
}

pub async fn establish_connection() -> Result<DbConn, DbErr> {
    let config = get_config().expect("Failed to read configuration.");
    let opt = ConnectOptions::new(config.database.connection_string().expose_secret().to_string());
    let db = Database::connect(opt).await?;
    Ok(db)
}

pub async fn init_db() {
    debug!("Checking DB connection...");
    let db =&*DB;
    let config = get_config().expect("Failed to read configuration.");
    let migration = env::var("MIGRATION").unwrap_or_else(|_| "".to_string());

    // ❗ If enabled, automatically migrate the database to the latest version when the application starts up.
    if migration == "auto" {
        if let Err(_) = Migrator::up(&db, None).await {
            panic!("Failed to run migration.");
        }
    }

    let conn = Database::connect(&*config.database.connection_string().expose_secret())
        .await
        .unwrap();
}