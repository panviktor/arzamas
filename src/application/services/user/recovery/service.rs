use crate::domain::ports::repositories::user::user_recovery_password_repository::UserRecoveryPasswdDomainRepository;
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use crate::domain::services::user::user_recovery_password_service::UserRecoveryPasswordDomainService;

pub struct UserRecoveryApplicationService<R, S>
where
    R: UserRecoveryPasswdDomainRepository,
    S: UserSecuritySettingsDomainRepository,
{
    user_recovery_domain_service: UserRecoveryPasswordDomainService<R, S>,
}

impl<R, S> UserRecoveryApplicationService<R, S>
where
    R: UserRecoveryPasswdDomainRepository,
    S: UserSecuritySettingsDomainRepository,
{
    pub fn new(user_recovery_domain_service: UserRecoveryPasswordDomainService<R, S>) -> Self {
        Self {
            user_recovery_domain_service,
        }
    }
}
