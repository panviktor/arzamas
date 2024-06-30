use crate::application::dto::user::user_authentication_request_dto::UserToken;
use crate::application::error::error::ApplicationError;
use crate::core::config::APP_SETTINGS;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use secrecy::ExposeSecret;

pub struct SharedService;

impl SharedService {
    pub async fn generate_token(payload: UserToken) -> Result<String, ApplicationError> {
        let header = Header::new(Algorithm::HS512);
        let result = jsonwebtoken::encode(
            &header,
            &payload,
            &EncodingKey::from_secret(APP_SETTINGS.jwt_secret.expose_secret().as_ref()),
        )
        .map_err(|e| ApplicationError::InternalServerError(e.to_string()))?;
        Ok(result)
    }

    pub fn decode_token(token: &str) -> Result<UserToken, ApplicationError> {
        let token = decode::<UserToken>(
            token,
            &DecodingKey::from_secret(APP_SETTINGS.jwt_secret.expose_secret().as_ref()),
            &Validation::new(Algorithm::HS512),
        )
        .map_err(|e| match e.kind() {
            ErrorKind::InvalidToken => {
                ApplicationError::ValidationError("Invalid token".to_string())
            }
            ErrorKind::ExpiredSignature => {
                ApplicationError::ValidationError("Token has expired".to_string())
            }
            ErrorKind::InvalidIssuer => {
                ApplicationError::ValidationError("Invalid issuer".to_string())
            }
            ErrorKind::InvalidAudience => {
                ApplicationError::ValidationError("Invalid audience".to_string())
            }
            _ => ApplicationError::InternalServerError(e.to_string()),
        })
        .map(|token_data| token_data.claims)?;

        Ok(token)
    }
}
