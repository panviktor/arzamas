use crate::application::dto::user::user_registration_request_dto::{
    CreateUserRequest, FindUserByIdRequest,
};
use crate::application::dto::user::user_registration_response_dto::CreatedUserResponse;
use crate::application::error::error::ApplicationError;
use crate::domain::entities::shared::Email;
use crate::domain::entities::user::UserRegistration;
use crate::domain::ports::email::email::EmailPort;
use crate::domain::repositories::user::user_parameters::FindUser;
use crate::domain::repositories::user::user_registration_repository::UserRegistrationDomainRepository;
use crate::domain::services::user::user_registration_service::UserRegistrationDomainService;
use std::sync::Arc;

pub struct UserRegistrationApplicationService<R, E>
where
    R: UserRegistrationDomainRepository,
    E: EmailPort,
{
    user_registration_domain_service: UserRegistrationDomainService<R>,
    email_service: Arc<E>,
}

impl<R, E> UserRegistrationApplicationService<R, E>
where
    R: UserRegistrationDomainRepository,
    E: EmailPort,
{
    pub fn new(
        user_registration_domain_service: UserRegistrationDomainService<R>,
        email_service: Arc<E>,
    ) -> Self {
        Self {
            user_registration_domain_service,
            email_service,
        }
    }

    pub async fn create_user(
        &self,
        dto_user: CreateUserRequest,
    ) -> Result<CreatedUserResponse, ApplicationError> {
        if dto_user.password != dto_user.password_confirm {
            return Err(ApplicationError::ValidationError(
                "Passwords do not match.".to_string(),
            ));
        }

        let email = Email(dto_user.email);
        let domain_user = UserRegistration::create(
            email,
            dto_user.username.to_string(),
            dto_user.password.to_string(),
        )?;
        let created_user = self
            .user_registration_domain_service
            .create_user(domain_user)
            .await?;

        let token = "token444";

        self.email_service
            .send_email(created_user.email.value(), "Registration complete", token)
            .await
            .map_err(|e| ApplicationError::ExternalServiceError(e.to_string()))?;

        // send-email.wait?;
        Ok(CreatedUserResponse::from(created_user))
    }

    pub async fn delete_user(&self, request: FindUserByIdRequest) -> Result<(), ApplicationError> {
        let find_user = FindUser {
            user_id: request.user_id,
        };
        self.user_registration_domain_service
            .delete_user(find_user)
            .await?;
        Ok(())
    }
}
