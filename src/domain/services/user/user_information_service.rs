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

    // get base user info

    // * setup user status

    // * user config (not security)

    // * ...
}
