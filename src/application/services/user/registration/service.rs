use crate::application::dto::user::user_registration_request_dto::{
    CreateUserRequest, FindUserByIdRequest, ValidateEmailRequest,
};
use crate::application::dto::user::user_registration_response_dto::CreatedUserResponse;
use crate::application::error::error::ApplicationError;
use crate::domain::entities::shared::value_objects::{EmailToken, UserId};
use crate::domain::entities::shared::{Email, Username};
use crate::domain::ports::email::email::EmailPort;
use crate::domain::ports::repositories::user::user_registration_dto::CreateUserDTO;
use crate::domain::ports::repositories::user::user_registration_repository::UserRegistrationDomainRepository;
use crate::domain::ports::repositories::user::user_shared_repository::UserSharedDomainRepository;
use crate::domain::services::user::user_registration_service::UserRegistrationDomainService;
use std::sync::Arc;

pub struct UserRegistrationApplicationService<R, U, E>
where
    R: UserRegistrationDomainRepository,
    U: UserSharedDomainRepository,
    E: EmailPort,
{
    user_registration_domain_service: UserRegistrationDomainService<R, U>,
    email_service: Arc<E>,
}

impl<R, U, E> UserRegistrationApplicationService<R, U, E>
where
    R: UserRegistrationDomainRepository,
    U: UserSharedDomainRepository,
    E: EmailPort,
{
    pub fn new(
        user_registration_domain_service: UserRegistrationDomainService<R, U>,
        email_service: Arc<E>,
    ) -> Self {
        Self {
            user_registration_domain_service,
            email_service,
        }
    }

    pub async fn create_user(
        &self,
        request: CreateUserRequest,
    ) -> Result<CreatedUserResponse, ApplicationError> {
        if request.password != request.password_confirm {
            return Err(ApplicationError::ValidationError(
                "Passwords do not match.".to_string(),
            ));
        }

        let email = Email(request.email);
        let username = Username(request.username);
        let create_user = CreateUserDTO::new(username, email, request.password);

        let created_user = self
            .user_registration_domain_service
            .create_user(create_user)
            .await
            .map_err(|e| ApplicationError::from(e))?;

        self.email_service
            .send_email(
                created_user.user.email.value(),
                "Registration complete",
                created_user.email_validation_token.value(),
            )
            .await
            .map_err(|e| ApplicationError::ExternalServiceError(e.to_string()))?;
        Ok(CreatedUserResponse::from(created_user.user))
    }

    pub async fn validate_email_user(
        &self,
        request: ValidateEmailRequest,
    ) -> Result<(), ApplicationError> {
        let email = Email::new(&request.email);
        let token = EmailToken(request.email_token);

        self.user_registration_domain_service
            .validate_email_user(email, token)
            .await?;
        Ok(())
    }

    pub async fn delete_user(&self, request: FindUserByIdRequest) -> Result<(), ApplicationError> {
        let find_user = UserId {
            user_id: request.user_id,
        };
        self.user_registration_domain_service
            .delete_user(find_user)
            .await?;
        Ok(())
    }
}
