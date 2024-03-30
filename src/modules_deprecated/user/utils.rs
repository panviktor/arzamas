use crate::application::error::response_error::AppResponseError;
use crate::modules::auth::utils::{get_user_security_token_by_id, get_user_settings_by_id};
use actix_web::HttpRequest;
use bip39::{Language, Mnemonic};
use entity::user_security_settings;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, DatabaseConnection, IntoActiveModel};
use url::Url;

pub(crate) async fn toggle_email(
    req: &HttpRequest,
    user_id: &str,
    two_factor: bool,
    db: &DatabaseConnection,
) -> Result<(), AppResponseError> {
    let settings = get_security_settings(req, user_id, db).await?;
    let mut settings = settings.into_active_model();
    settings.two_factor_email = Set(two_factor);
    settings.update(db).await?;
    Ok(())
}

/// need refactoring to valid google app scheme?

fn generate_totp_uri(secret: &str, user_id: &str, issuer: &str) -> String {
    let mut url = Url::parse("otpauth://totp/").unwrap();
    url.path_segments_mut()
        .unwrap()
        .push(&format!("{}:{}", issuer, user_id));

    url.query_pairs_mut()
        .append_pair("secret", secret)
        .append_pair("issuer", issuer)
        .append_pair("algorithm", "SHA1")
        .append_pair("digits", "6")
        .append_pair("period", "30");

    url.to_string()
}

pub(crate) async fn generate_2fa_secret(
    req: &HttpRequest,
    user_id: &str,
    db: &DatabaseConnection,
) -> Result<AuthenticationAppInformation, AppResponseError> {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).expect("Failed to fill bytes with randomness");
    let mnemonic = Mnemonic::from_entropy(&secret, Language::English).unwrap();
    let mnemonic = mnemonic.phrase().to_string();
    let base32_secret = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret);
    let url = generate_totp_uri(&base32_secret, user_id, "Arzamas"); //not impl yet

    let otp_token = get_user_security_token_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?;

    let mut otp_token = otp_token.into_active_model();
    otp_token.otp_app_hash = Set(Some(base32_secret.clone()));
    otp_token.otp_app_mnemonic = Set(Some(mnemonic.clone()));
    otp_token.update(db).await?;

    let json = AuthenticationAppInformation {
        mnemonic,
        base32_secret,
    };

    Ok(json)
}

pub(crate) async fn get_security_settings(
    req: &HttpRequest,
    user_id: &str,
    db: &DatabaseConnection,
) -> Result<user_security_settings::Model, AppResponseError> {
    let settings = get_user_settings_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?;
    Ok(settings)
}
