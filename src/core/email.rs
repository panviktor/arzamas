use lazy_static::lazy_static;

use lettre::{
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport,
    Tokio1Executor,
};

use secrecy::ExposeSecret;
use crate::core::config::{get_config};

lazy_static! {
   pub static ref MAILER: AsyncSmtpTransport<Tokio1Executor> = {
        async_std::task::block_on(async {
            let config = get_config().expect("Failed to read configuration.");
            let server = config.email_settings.email_server;
            let user = config.email_settings.email_user;
            let pass = config.email_settings.email_pass.expose_secret();
            let creds = Credentials::new(user.to_string(), pass.to_string());
             AsyncSmtpTransport::<Tokio1Executor>::relay(&server)
                .unwrap()
                .credentials(creds)
                .build()
        })
    };
}
