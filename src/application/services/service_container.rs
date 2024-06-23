use crate::application::services::note::service::NoteApplicationService;
use crate::application::services::user::authentication::service::UserAuthenticationApplicationService;
use crate::application::services::user::information::service::UserInformationApplicationService;
use crate::application::services::user::recovery::service::UserRecoveryApplicationService;
use crate::application::services::user::registration::service::UserRegistrationApplicationService;
use crate::application::services::user::security::service::UserSecurityApplicationService;
use crate::domain::services::note::note_service::NoteDomainService;
use crate::domain::services::user::user_authentication_service::UserAuthenticationDomainService;
use crate::domain::services::user::user_information_service::UserInformationDomainService;
use crate::domain::services::user::user_recovery_password_service::UserRecoveryPasswordDomainService;
use crate::domain::services::user::user_registration_service::UserRegistrationDomainService;
use crate::domain::services::user::user_security_settings_service::UserSecuritySettingsDomainService;
use crate::infrastructure::cache::redis_adapter::RedisAdapter;
use crate::infrastructure::email::lettre_email_adapter::LettreEmailAdapter;

use crate::infrastructure::repository::sea_orm::note::seaorm_note::SeaOrmNoteRepository;
use crate::infrastructure::repository::sea_orm::user::seaorm_user::SeaOrmUserSharedRepository;
use crate::infrastructure::repository::sea_orm::user::seaorm_user_authentication::SeaOrmUserAuthenticationRepository;
use crate::infrastructure::repository::sea_orm::user::seaorm_user_recovery::SeaOrmUserRecoveryRepository;
use crate::infrastructure::repository::sea_orm::user::seaorm_user_registration::SeaOrmUserRegistrationRepository;
use crate::infrastructure::repository::sea_orm::user::seaorm_user_security::SeaOrmUserSecurityRepository;
use deadpool_redis::Pool;
use lettre::AsyncSmtpTransport;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

pub struct ServiceContainer {
    pub user_registration_service: UserRegistrationApplicationService<
        SeaOrmUserRegistrationRepository,
        SeaOrmUserSharedRepository,
        LettreEmailAdapter,
    >,

    pub user_authentication_service: UserAuthenticationApplicationService<
        SeaOrmUserAuthenticationRepository,
        SeaOrmUserSharedRepository,
        LettreEmailAdapter,
        RedisAdapter,
    >,

    pub user_information_service: UserInformationApplicationService<SeaOrmUserSharedRepository>,

    pub user_security_service: UserSecurityApplicationService<
        SeaOrmUserSecurityRepository,
        SeaOrmUserSharedRepository,
        LettreEmailAdapter,
        RedisAdapter,
    >,

    pub user_recovery_service: UserRecoveryApplicationService<
        SeaOrmUserRecoveryRepository,
        SeaOrmUserSecurityRepository,
        LettreEmailAdapter,
        RedisAdapter,
    >,

    pub note_service: NoteApplicationService<SeaOrmNoteRepository>,
}

impl ServiceContainer {
    pub fn new(
        database: DatabaseConnection,
        email_transport: AsyncSmtpTransport<lettre::Tokio1Executor>,
        redis_pool: Pool,
    ) -> Self {
        let db_arc = Arc::new(database);

        let email_service = Arc::new(LettreEmailAdapter::new(email_transport));
        let redis_service = Arc::new(RedisAdapter::new(redis_pool));

        // Shared
        let user_shared_repository = Arc::new(SeaOrmUserSharedRepository::new(db_arc.clone()));

        // User registration services
        let user_registration_repository = SeaOrmUserRegistrationRepository::new(db_arc.clone());
        let user_registration_domain_service = UserRegistrationDomainService::new(
            user_registration_repository,
            user_shared_repository.clone(),
        );
        let user_registration_service = UserRegistrationApplicationService::new(
            user_registration_domain_service,
            email_service.clone(),
        );

        // User authentication services
        let user_authentication_repository =
            SeaOrmUserAuthenticationRepository::new(db_arc.clone());
        let user_authentication_domain_service = UserAuthenticationDomainService::new(
            user_authentication_repository.clone(),
            user_shared_repository.clone(),
        );
        let user_authentication_service = UserAuthenticationApplicationService::new(
            user_authentication_domain_service,
            redis_service.clone(),
            email_service.clone(),
        );

        // User information services
        let user_information_domain_service =
            UserInformationDomainService::new(user_shared_repository.clone());
        let user_information_service =
            UserInformationApplicationService::new(user_information_domain_service);

        // User security services
        let user_security_repository = Arc::new(SeaOrmUserSecurityRepository::new(db_arc.clone()));
        let user_security_domain_service = UserSecuritySettingsDomainService::new(
            user_security_repository.clone(),
            user_shared_repository.clone(),
        );
        let user_security_service = UserSecurityApplicationService::new(
            user_security_domain_service,
            redis_service.clone(),
            email_service.clone(),
        );

        // User recovery services
        let recovery_passwd_repository = SeaOrmUserRecoveryRepository::new(db_arc.clone());
        let user_recovery_domain_service = UserRecoveryPasswordDomainService::new(
            recovery_passwd_repository,
            user_security_repository,
        );
        let user_recovery_service = UserRecoveryApplicationService::new(
            user_recovery_domain_service,
            redis_service.clone(),
            email_service.clone(),
        );

        // Note services
        let note_repository = SeaOrmNoteRepository::new(db_arc.clone());
        let note_domain_service = NoteDomainService::new(note_repository);
        let note_service = NoteApplicationService::new(note_domain_service);

        ServiceContainer {
            user_registration_service,
            user_authentication_service,
            user_information_service,
            user_security_service,
            user_recovery_service,
            note_service,
        }
    }
}
