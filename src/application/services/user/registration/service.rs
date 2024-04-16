use crate::application::dto::user::user_registration_request_dto::{
    CreateUserRequest, FindUserByIdRequest, ValidateEmailRequest,
};
use crate::application::dto::user::user_registration_response_dto::CreatedUserResponse;
use crate::application::error::error::ApplicationError;
use crate::domain::entities::shared::{Email, Username};

use crate::domain::entities::shared::value_objects::EmailToken;
use crate::domain::ports::email::email::EmailPort;
use crate::domain::repositories::user::user_registration_parameters::CreateUserDTO;
use crate::domain::repositories::user::user_registration_repository::UserRegistrationDomainRepository;
use crate::domain::repositories::user::user_shared_parameters::FindUserByIdDTO;
use crate::domain::repositories::user::user_shared_repository::UserDomainRepository;
use crate::domain::services::user::user_registration_service::UserRegistrationDomainService;
use std::sync::Arc;

pub struct UserRegistrationApplicationService<R, U, E>
where
    R: UserRegistrationDomainRepository,
    U: UserDomainRepository,
    E: EmailPort,
{
    user_registration_domain_service: UserRegistrationDomainService<R, U>,
    email_service: Arc<E>,
}

impl<R, U, E> UserRegistrationApplicationService<R, U, E>
where
    R: UserRegistrationDomainRepository,
    U: UserDomainRepository,
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
    ) -> Result<CreatedUserResponse, ApplicationError> {
        todo!()
    }

    pub async fn delete_user(&self, request: FindUserByIdRequest) -> Result<(), ApplicationError> {
        let find_user = FindUserByIdDTO {
            user_id: request.user_id,
        };
        self.user_registration_domain_service
            .delete_user(find_user)
            .await?;
        Ok(())
    }
}
