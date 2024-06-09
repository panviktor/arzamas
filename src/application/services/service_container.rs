use crate::application::services::note::service::NoteApplicationService;
use crate::application::services::user::authentication::service::UserAuthenticationApplicationService;
use crate::application::services::user::information::service::UserInformationApplicationService;
use crate::application::services::user::registration::service::UserRegistrationApplicationService;
use crate::domain::services::note::note_service::NoteDomainService;
use crate::domain::services::user::user_authentication_service::UserAuthenticationDomainService;
use crate::domain::services::user::user_information_service::UserInformationDomainService;
use crate::domain::services::user::user_registration_service::UserRegistrationDomainService;
use crate::infrastructure::cache::redis_adapter::RedisAdapter;
use crate::infrastructure::email::lettre_email_adapter::LettreEmailAdapter;
use crate::infrastructure::repository::note::seaorm_note::SeaOrmNoteRepository;
use crate::infrastructure::repository::user::seaorm_user::SeaOrmUserSharedRepository;
use crate::infrastructure::repository::user::seaorm_user_authentication::SeaOrmUserAuthenticationRepository;
use crate::infrastructure::repository::user::seaorm_user_registration::SeaOrmUserRegistrationRepository;
use deadpool_redis::Pool;
use lettre::AsyncSmtpTransport;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

pub struct ServiceContainer {
    pub note_application_service: Arc<NoteApplicationService<SeaOrmNoteRepository>>,
    pub user_registration_service: Arc<
        UserRegistrationApplicationService<
            SeaOrmUserRegistrationRepository,
            SeaOrmUserSharedRepository,
            LettreEmailAdapter,
        >,
    >,
    pub user_authentication_service: Arc<
        UserAuthenticationApplicationService<
            SeaOrmUserAuthenticationRepository,
            LettreEmailAdapter,
            RedisAdapter,
        >,
    >,

    pub user_information_service:
        Arc<UserInformationApplicationService<SeaOrmUserSharedRepository>>,
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

        let note_repository = SeaOrmNoteRepository::new(db_arc.clone());
        let note_domain_service = NoteDomainService::new(note_repository);
        let note_application_service = Arc::new(NoteApplicationService::new(note_domain_service));

        let user_shared_repository = Arc::new(SeaOrmUserSharedRepository::new(db_arc.clone()));
        let user_registration_repository = SeaOrmUserRegistrationRepository::new(db_arc.clone());

        let user_registration_domain_service = UserRegistrationDomainService::new(
            user_registration_repository,
            user_shared_repository.clone(),
        );
        let user_registration_service = Arc::new(UserRegistrationApplicationService::new(
            user_registration_domain_service,
            email_service.clone(),
        ));

        let user_authentication_repository =
            Arc::new(SeaOrmUserAuthenticationRepository::new(db_arc.clone()));
        let user_authentication_domain_service =
            UserAuthenticationDomainService::new(user_authentication_repository.clone());

        let user_authentication_service = Arc::new(UserAuthenticationApplicationService::new(
            user_authentication_domain_service,
            redis_service.clone(),
            email_service.clone(),
        ));

        let user_information_domain_service =
            UserInformationDomainService::new(user_shared_repository.clone());
        let user_information_service = Arc::new(UserInformationApplicationService::new(
            user_information_domain_service,
        ));

        ServiceContainer {
            note_application_service,
            user_registration_service,
            user_authentication_service,
            user_information_service,
        }
    }
}
