use crate::domain::entities::shared::value_objects::OtpToken;
use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::user::user_security_settings::{
    ConfirmEnableApp2FA, ConfirmEnableEmail2FA, DisableApp2FA, InitiateDeleteUserResponse,
    UserChangeEmail, UserSecuritySettings,
};
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::{DomainError, PersistenceError, ValidationError};

use crate::domain::entities::user::user_registration::UserRegistrationError;
use crate::domain::error::ExternalServiceError::Custom;
use crate::domain::error::PersistenceError::Retrieve;
use crate::domain::error::ValidationError::BusinessRuleViolation;
use crate::domain::ports::repositories::user::user_security_settings_dto::{
    ActivateEmail2FADTO, ChangeEmailDTO, ChangePasswordDTO, ConfirmChangeApp2FADTO,
    ConfirmDeleteUserDTO, ConfirmEmail2FADTO, ConfirmEmailDTO, SecuritySettingsUpdateDTO,
};
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use crate::domain::ports::repositories::user::user_shared_repository::UserSharedDomainRepository;
use crate::domain::services::shared::SharedDomainService;
use crate::domain::services::user::{
    UserCredentialService, UserValidationService, ValidationServiceError,
};
use chrono::{DateTime, Duration, Utc};
use getrandom::getrandom;
use std::sync::Arc;
use tokio::join;
use url::Url;

pub struct UserSecuritySettingsDomainService<S, U>
where
    S: UserSecuritySettingsDomainRepository,
    U: UserSharedDomainRepository,
{
    user_security_settings_repository: Arc<S>,
    user_repository: Arc<U>,
}

impl<S, U> UserSecuritySettingsDomainService<S, U>
where
    S: UserSecuritySettingsDomainRepository,
    U: UserSharedDomainRepository,
{
    pub fn new(user_security_settings_repository: Arc<S>, user_repository: Arc<U>) -> Self {
        Self {
            user_security_settings_repository,
            user_repository,
        }
    }

    pub async fn get_user_session(
        &self,
        user: UserId,
        session_id: &str,
    ) -> Result<UserSession, DomainError> {
        let session = self
            .user_security_settings_repository
            .get_user_session(&user, session_id)
            .await?;
        Ok(session)
    }

    pub async fn get_user_sessions(&self, user: UserId) -> Result<Vec<UserSession>, DomainError> {
        let sessions = self
            .user_security_settings_repository
            .get_user_sessions(&user)
            .await?;
        Ok(sessions)
    }

    pub async fn change_password(&self, request: ChangePasswordDTO) -> Result<(), DomainError> {
        UserValidationService::validate_passwd(&request.new_password)
            .map_err(UserRegistrationError::InvalidPassword)?;

        let new_hash = UserCredentialService::generate_password_hash(&request.new_password)
            .map_err(|e| DomainError::Unknown(format!("Password hashing failed: {:?}", e)))?;

        // Retrieve the old password hash from the database
        let old_db_hash = self
            .user_security_settings_repository
            .get_old_passwd(&request.user_id)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(Retrieve(format!(
                    "Failed to retrieve old password hash for user. Error: {}",
                    e
                )))
            })?;

        // Validate that the current password matches the stored hash
        match UserCredentialService::credential_validator(&request.current_password, &old_db_hash) {
            Ok(true) => {}
            Ok(false) => {
                return Err(DomainError::ValidationError(ValidationError::InvalidData(
                    "Current password is incorrect".to_string(),
                )));
            }
            Err(_) => {
                return Err(DomainError::Unknown(
                    "Credential validation failed".to_string(),
                ));
            }
        }

        // Validate that the new password is different from the old password
        if request.current_password == request.new_password {
            return Err(DomainError::ValidationError(BusinessRuleViolation(
                "New password must be different from the current password".to_string(),
            )));
        }

        //Set the new password in the database
        self.user_security_settings_repository
            .set_new_password(&request.user_id, new_hash, Utc::now())
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Update(format!(
                    "Failed to set new password: {}",
                    e
                )))
            })?;
        Ok(())
    }

    pub async fn change_email(
        &self,
        request: ChangeEmailDTO,
    ) -> Result<UserChangeEmail, DomainError> {
        UserValidationService::validate_email(&request.new_email)
            .map_err(UserRegistrationError::InvalidEmail)?;

        let get_user_future = self.user_repository.get_base_user_by_id(&request.user_id);
        let check_email_future = self.user_repository.exists_with_email(&request.new_email);
        let (user_result, email_exists_result) = join!(get_user_future, check_email_future);

        // Handle the results of the concurrent operations
        let user = user_result.map_err(|e| {
            DomainError::PersistenceError(Retrieve(format!("Failed to retrieve user: {}", e)))
        })?;

        if user.email == request.new_email {
            return Err(DomainError::PersistenceError(Retrieve(
                "New email cannot be the same as the current email".into(),
            )));
        };

        if email_exists_result.map_err(|e| {
            DomainError::PersistenceError(Retrieve(format!(
                "Failed to check if email exists: {}",
                e
            )))
        })? {
            return Err(UserRegistrationError::InvalidEmail(
                ValidationServiceError::BusinessRuleViolation("Email already exists".to_string()),
            )
            .into());
        }

        let (confirmation_token, confirmation_token_hash, expiry) =
            self.generate_email_token(64).await?;

        self.user_security_settings_repository
            .store_change_email_confirmation_token(
                request.user_id,
                confirmation_token_hash,
                expiry,
                request.new_email.clone(),
            )
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Update(format!(
                    "Failed to store email confirmation token: {}",
                    e
                )))
            })?;

        let outcome = UserChangeEmail {
            new_email: request.new_email,
            old_email: user.email,
            email_validation_token: confirmation_token,
        };

        Ok(outcome)
    }

    pub async fn cancel_email_change(&self, user_id: UserId) -> Result<(), DomainError> {
        self.user_security_settings_repository
            .clear_email_confirmation_token(&user_id)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Update(format!(
                    "Failed to clear email confirmation token: {}",
                    e
                )))
            })?;
        Ok(())
    }

    pub async fn confirm_email(&self, request: ConfirmEmailDTO) -> Result<(), DomainError> {
        let confirmation = self
            .user_security_settings_repository
            .get_change_email_confirmation(&request.user_id)
            .await?;

        if SharedDomainService::validate_hash(&request.token.value(), &confirmation.otp_hash) {
            let now = Utc::now();
            if confirmation.expiry > now {
                let (complete_verification_result, update_email_result) = join!(
                    self.user_security_settings_repository
                        .clear_email_confirmation_token(&request.user_id),
                    self.user_security_settings_repository
                        .update_main_user_email(&request.user_id, confirmation.new_email, now)
                );

                complete_verification_result?;
                update_email_result?;

                Ok(())
            } else {
                Err(DomainError::ValidationError(ValidationError::InvalidData(
                    "The confirmation token has expired.\n\
                     Please log in to the app again to generate a new confirmation token.\n\
                     If you are using 2FA email authentication, please check your old email."
                        .to_string(),
                )))
            }
        } else {
            Err(DomainError::ValidationError(ValidationError::InvalidData(
                "The validation code you entered is incorrect.\n
                 Please try again."
                    .to_string(),
            )))
        }
    }

    pub async fn get_security_settings(
        &self,
        request: UserId,
    ) -> Result<UserSecuritySettings, DomainError> {
        let security_settings = self
            .user_security_settings_repository
            .get_security_settings(&request)
            .await?;
        Ok(security_settings)
    }

    pub async fn update_security_settings(
        &self,
        request: SecuritySettingsUpdateDTO,
    ) -> Result<(), DomainError> {
        let now = Utc::now();
        self.user_security_settings_repository
            .update_security_settings(request, now)
            .await?;
        Ok(())
    }

    pub async fn enable_email_2fa(
        &self,
        request: ActivateEmail2FADTO,
    ) -> Result<ConfirmEnableEmail2FA, DomainError> {
        UserValidationService::validate_email(&request.email)?;
        let (user_result, security_settings_result) = join!(
            self.user_repository.get_base_user_by_id(&request.user_id),
            self.user_security_settings_repository
                .get_security_settings(&request.user_id)
        );

        // Handle potential errors from the concurrent operations
        let user = user_result?;
        let security_settings = security_settings_result?;

        // Check if email 2FA is already enabled
        if security_settings.two_factor_email {
            return Err(DomainError::ValidationError(BusinessRuleViolation(
                "Two-factor authentication via email is already enabled.".to_string(),
            )));
        }

        // Check if the email matches the user's registered email
        if user.email != request.email {
            return Err(DomainError::PersistenceError(Retrieve(
                "Invalid email for activation. Please use the email associated with the user."
                    .into(),
            )));
        }

        // Generate a new token
        let (confirmation_token, confirmation_token_hash, expiry) =
            self.generate_email_token(32).await?;

        // Save the token
        self.user_security_settings_repository
            .save_email_2fa_token(request.user_id, confirmation_token_hash, expiry)
            .await?;

        Ok(ConfirmEnableEmail2FA::new(user.email, confirmation_token))
    }

    pub async fn confirm_email_2fa(&self, request: ConfirmEmail2FADTO) -> Result<(), DomainError> {
        let confirmation_result = self
            .user_security_settings_repository
            .get_email_2fa_token(&request.user_id)
            .await;

        let confirmation = match confirmation_result {
            Ok(confirmation) => confirmation,
            Err(e) => {
                return Err(DomainError::PersistenceError(Retrieve(
                    format!(
                        "Failed to retrieve the 2FA token.\n\
                     Please ensure that the process of enabling 2FA has started \
                     and the token has been confirmed before trying again.\n\
                     Error details: {}",
                        e
                    )
                    .into(),
                )))
            }
        };

        if SharedDomainService::validate_hash(request.token.value(), &confirmation.otp_hash) {
            let now = Utc::now();
            if confirmation.expiry > now {
                self.user_security_settings_repository
                    .toggle_email_2fa(&request.user_id, true, now)
                    .await?;
                return Ok(());
            } else {
                // Token expired
                Err(DomainError::ValidationError(ValidationError::InvalidData(
                    "The confirmation token has expired. Please request a new token.".to_string(),
                )))
            }
        } else {
            Err(DomainError::ValidationError(ValidationError::InvalidData(
                "The validation code you entered is incorrect. Please try again.".to_string(),
            )))
        }
    }

    pub async fn disable_email_2fa(
        &self,
        user_id: UserId,
    ) -> Result<ConfirmEnableEmail2FA, DomainError> {
        let (user_result, security_settings_result) = join!(
            self.user_repository.get_base_user_by_id(&user_id),
            self.user_security_settings_repository
                .get_security_settings(&user_id)
        );

        // Handle potential errors from the concurrent operations
        let user = user_result?;
        let security_settings = security_settings_result?;

        // Check if email 2FA is already disabled
        if !security_settings.two_factor_email {
            return Err(DomainError::ValidationError(BusinessRuleViolation(
                "Two-factor authentication via email is already disabled.".to_string(),
            )));
        }
        // Generate a new token
        let (disable_token, disable_token_hash, expiry) = self.generate_email_token(32).await?;

        // Save the token
        self.user_security_settings_repository
            .save_email_2fa_token(user_id, disable_token_hash, expiry)
            .await?;

        Ok(ConfirmEnableEmail2FA::new(user.email, disable_token))
    }

    pub async fn confirm_disable_email_2fa(
        &self,
        request: ConfirmEmail2FADTO,
    ) -> Result<(), DomainError> {
        let confirmation_result = self
            .user_security_settings_repository
            .get_email_2fa_token(&request.user_id)
            .await;

        let confirmation = match confirmation_result {
            Ok(confirmation) => confirmation,
            Err(e) => {
                return Err(DomainError::PersistenceError(Retrieve(
                    format!(
                        "Failed to retrieve the 2FA token.\n\
                     Please ensure that the process of disabling 2FA has started \
                     and the token has been confirmed before trying again.\n\
                     Error details: {}",
                        e
                    )
                    .into(),
                )));
            }
        };

        if SharedDomainService::validate_hash(request.token.value(), &confirmation.otp_hash) {
            let now = Utc::now();
            if confirmation.expiry > now {
                self.user_security_settings_repository
                    .toggle_email_2fa(&request.user_id, false, now)
                    .await?;
                Ok(())
            } else {
                // Token expired
                Err(DomainError::ValidationError(ValidationError::InvalidData(
                    "The disable confirmation token has expired. Please request a new token."
                        .to_string(),
                )))
            }
        } else {
            Err(DomainError::ValidationError(ValidationError::InvalidData(
                "The validation code you entered is incorrect. Please try again.".to_string(),
            )))
        }
    }

    pub async fn enable_app_2fa(
        &self,
        user_id: UserId,
    ) -> Result<ConfirmEnableApp2FA, DomainError> {
        let (user_result, security_settings_result) = join!(
            self.user_repository.get_base_user_by_id(&user_id),
            self.user_security_settings_repository
                .get_security_settings(&user_id)
        );

        // Handle potential errors from the concurrent operations
        let user = user_result?;
        let security_settings = security_settings_result?;

        // Check if email 2FA is already enabled
        if security_settings.two_factor_authenticator_app {
            return Err(DomainError::ValidationError(BusinessRuleViolation(
                "Two-factor authentication via App is already enabled.".to_string(),
            )));
        }

        let (confirmation_token, confirmation_token_hash, expiry) =
            self.generate_email_token(32).await?;

        let mut secret = [0u8; 32];
        getrandom(&mut secret).map_err(|e| {
            DomainError::ExternalServiceError(Custom(format!("Getrandom error: {}", e)))
        })?;
        let base32_secret = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret);

        self.user_security_settings_repository
            .save_app_2fa_secret(
                user_id,
                base32_secret.clone(),
                confirmation_token_hash,
                expiry,
            )
            .await?;

        let url_for_app = Self::generate_totp_uri(&base32_secret, &user.username, "Arzamas")?;

        Ok(ConfirmEnableApp2FA::new(
            user.email,
            confirmation_token,
            base32_secret,
            url_for_app,
        ))
    }

    pub async fn confirm_enable_app_2fa(
        &self,
        request: ConfirmChangeApp2FADTO,
    ) -> Result<(), DomainError> {
        let app_token = self
            .user_security_settings_repository
            .get_app_2fa_token(&request.user_id)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(Retrieve(format!("Failed to retrieve user: {}", e)))
            })?;

        if SharedDomainService::validate_hash(request.email_code.value(), &app_token.otp_hash) {
            let now = Utc::now();
            if app_token.expiry > now {
                UserValidationService::verify_totp(&app_token.secret, request.app_code.value())?;

                Ok(self
                    .user_security_settings_repository
                    .toggle_app_2fa(&request.user_id, true, now)
                    .await?)
            } else {
                Err(DomainError::ValidationError(ValidationError::InvalidData(
                    "The confirmation token has expired. Please request a new token.".to_string(),
                )))
            }
        } else {
            Err(DomainError::ValidationError(ValidationError::InvalidData(
                "The validation code you entered is incorrect. Please try again.".to_string(),
            )))
        }
    }

    pub async fn disable_app_2fa(&self, user_id: UserId) -> Result<DisableApp2FA, DomainError> {
        let (user_result, security_settings_result) = join!(
            self.user_repository.get_base_user_by_id(&user_id),
            self.user_security_settings_repository
                .get_security_settings(&user_id)
        );

        // Handle potential errors from the concurrent operations
        let user = user_result?;
        let security_settings = security_settings_result?;

        // Check if email 2FA is already enabled
        if !security_settings.two_factor_authenticator_app {
            return Err(DomainError::ValidationError(BusinessRuleViolation(
                "Two-factor authentication via App is already disable.".to_string(),
            )));
        }
        let (confirmation_token, confirmation_token_hash, expiry) =
            self.generate_email_token(32).await?;

        self.user_security_settings_repository
            .store_token_for_remove_user(user_id, confirmation_token_hash, expiry)
            .await?;

        Ok(DisableApp2FA::new(user.email, confirmation_token))
    }

    pub async fn confirm_disable_app_2fa(
        &self,
        request: ConfirmChangeApp2FADTO,
    ) -> Result<(), DomainError> {
        //
        // Retrieve the 2FA token
        let app_token = self
            .user_security_settings_repository
            .get_token_for_disable_app_2fa(&request.user_id)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(Retrieve(format!("Failed to retrieve user: {}", e)))
            })?;

        if SharedDomainService::validate_hash(request.email_code.value(), &app_token.token_hash) {
            let now = Utc::now();
            if app_token.expiry > now {
                UserValidationService::verify_totp(&app_token.secret, request.app_code.value())?;
                let disable_2fa_future = self.user_security_settings_repository.toggle_app_2fa(
                    &request.user_id,
                    false,
                    now,
                );
                let remove_secret_future = self
                    .user_security_settings_repository
                    .remove_app_2fa_secret(&request.user_id);
                let (disable_2fa_result, remove_secret_result) =
                    join!(disable_2fa_future, remove_secret_future);

                disable_2fa_result?;
                remove_secret_result?;

                Ok(())
            } else {
                Err(DomainError::ValidationError(ValidationError::InvalidData(
                    "The disable confirmation token has expired. Please request a new token."
                        .to_string(),
                )))
            }
        } else {
            Err(DomainError::ValidationError(ValidationError::InvalidData(
                "The validation code you entered is incorrect. Please try again.".to_string(),
            )))
        }
    }

    pub async fn initiate_delete_user(
        &self,
        user_id: UserId,
    ) -> Result<InitiateDeleteUserResponse, DomainError> {
        let (remove_token, remove_token_hash, expiry) = self.generate_email_token(32).await?;

        let user = self
            .user_repository
            .get_base_user_by_id(&user_id)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(Retrieve(format!("Failed to retrieve user: {}", e)))
            })?;

        self.user_security_settings_repository
            .store_token_for_remove_user(user_id, remove_token_hash, expiry)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Update(format!(
                    "Failed to store remove user token: {}",
                    e
                )))
            })?;

        let response = InitiateDeleteUserResponse {
            email: user.email,
            token: remove_token,
        };
        Ok(response)
    }

    pub async fn confirm_remove_user(
        &self,
        request: ConfirmDeleteUserDTO,
    ) -> Result<(), DomainError> {
        let stored_token = self
            .user_security_settings_repository
            .get_token_for_remove_user(&request.user_id)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(Retrieve(format!(
                    "Failed to retrieve remove user token: {}",
                    e
                )))
            })?;

        if !SharedDomainService::validate_hash(&request.token.value(), &stored_token.otp_hash) {
            return Err(DomainError::ValidationError(ValidationError::InvalidData(
                "The validation code you entered is incorrect. Please try again.".to_string(),
            )));
        }

        if stored_token.expiry < Utc::now() {
            return Err(DomainError::ValidationError(ValidationError::InvalidData(
                "The remove user token has expired. Please request a new token.".to_string(),
            )));
        }

        self.user_security_settings_repository
            .delete_user(request.user_id)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Delete(format!(
                    "Failed to remove user: {}",
                    e
                )))
            })?;

        Ok(())
    }
}

impl<S, U> UserSecuritySettingsDomainService<S, U>
where
    S: UserSecuritySettingsDomainRepository,
    U: UserSharedDomainRepository,
{
    async fn generate_email_token(
        &self,
        length: usize,
    ) -> Result<(OtpToken, String, DateTime<Utc>), DomainError> {
        let token = SharedDomainService::generate_token(length)?;
        let email_token = OtpToken::new(&token);
        let token_hash = SharedDomainService::hash_token(&token);
        let expiry = Utc::now() + Duration::days(1);
        Ok((email_token, token_hash, expiry))
    }

    fn generate_totp_uri(
        secret: &str,
        user_name: &str,
        issuer: &str,
    ) -> Result<String, DomainError> {
        let mut url = Url::parse("otpauth://totp/").map_err(|e| {
            DomainError::ExternalServiceError(Custom(format!("Failed to parse base URL: {}", e)))
        })?;

        url.path_segments_mut()
            .map_err(|_| {
                DomainError::ExternalServiceError(Custom(
                    "Failed to get mutable path segments".to_string(),
                ))
            })?
            .push(&format!("{}:{}", issuer, user_name));

        url.query_pairs_mut()
            .append_pair("secret", secret)
            .append_pair("issuer", issuer)
            .append_pair("algorithm", "SHA1")
            .append_pair("digits", "6")
            .append_pair("period", "30");

        Ok(url.to_string())
    }
}
