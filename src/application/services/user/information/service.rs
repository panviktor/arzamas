use crate::application::dto::user::user_shared_request_dto::UserByIdRequest;
use crate::application::dto::user::user_shared_response_dto::BaseUserResponse;
use crate::application::error::error::ApplicationError;
use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::ports::repositories::user::user_shared_repository::UserSharedDomainRepository;
use crate::domain::services::user::user_information_service::UserInformationDomainService;

pub struct UserInformationApplicationService<U>
where
    U: UserSharedDomainRepository,
{
    user_information_domain_service: UserInformationDomainService<U>,
}

impl<U> UserInformationApplicationService<U>
where
    U: UserSharedDomainRepository,
{
    pub fn new(user_information_domain_service: UserInformationDomainService<U>) -> Self {
        Self {
            user_information_domain_service,
        }
    }

    pub async fn get_user_information(
        &self,
        request: UserByIdRequest,
    ) -> Result<BaseUserResponse, ApplicationError> {
        let id = UserId::new(&request.user_id);
        let user = self
            .user_information_domain_service
            .get_user_info(id)
            .await?;

        Ok(user.into())
    }
}
