use crate::domain::entities::user::user_authentication::UserAuthentication;
use crate::domain::error::DomainError;
use crate::domain::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByUsernameDTO,
};
use async_trait::async_trait;

#[async_trait]
pub trait UserAuthenticationDomainRepository {
    async fn get_user_by_email(
        &self,
        user: FindUserByEmailDTO,
    ) -> Result<UserAuthentication, DomainError>;

    async fn get_user_by_username(
        &self,
        user: FindUserByUsernameDTO,
    ) -> Result<UserAuthentication, DomainError>;
}
