use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::user::UserBase;
use crate::domain::error::DomainError;
use crate::domain::ports::repositories::user::user_shared_repository::UserSharedDomainRepository;
use std::sync::Arc;

pub struct UserInformationDomainService<U>
where
    U: UserSharedDomainRepository,
{
    user_repository: Arc<U>,
}
impl<U> UserInformationDomainService<U>
where
    U: UserSharedDomainRepository,
{
    pub fn new(user_repository: Arc<U>) -> Self {
        Self { user_repository }
    }
    pub async fn get_user_info(&self, user: UserId) -> Result<UserBase, DomainError> {
        self.user_repository.get_base_user_by_id(&user).await
    }
}
