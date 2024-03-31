use crate::application::services::note::service::NoteApplicationService;
use crate::application::services::user::registration::service::UserRegistrationApplicationService;
use crate::domain::services::note::note_service::NoteDomainService;
use crate::domain::services::user::user_registration_service::UserRegistrationDomainService;
use crate::infrastructure::email::lettre_email_adapter::LettreEmailAdapter;
use crate::infrastructure::repository::note::seaorm_note::SeaOrmNoteRepository;
use crate::infrastructure::repository::user::seaorm_user::SeaOrmUserRepository;
use crate::infrastructure::repository::user::seaorm_user_registration::SeaOrmUserRegistrationRepository;
use lettre::AsyncSmtpTransport;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

pub struct ServiceContainer {
    pub note_application_service: Arc<NoteApplicationService<SeaOrmNoteRepository>>,
    pub user_registration_service: Arc<
        UserRegistrationApplicationService<
            SeaOrmUserRegistrationRepository,
            SeaOrmUserRepository,
            LettreEmailAdapter,
        >,
    >,
}

impl ServiceContainer {
    pub fn new(
        database: DatabaseConnection,
        email_transport: AsyncSmtpTransport<lettre::Tokio1Executor>,
    ) -> Self {
        let db_arc = Arc::new(database);

        let email_service = Arc::new(LettreEmailAdapter::new(email_transport));

        let note_repository = SeaOrmNoteRepository::new(db_arc.clone());
        let note_domain_service = NoteDomainService::new(note_repository);
        let note_application_service = Arc::new(NoteApplicationService::new(note_domain_service));

        let user_repository = SeaOrmUserRepository::new(db_arc.clone());
        let user_registration_repository = SeaOrmUserRegistrationRepository::new(db_arc.clone());

        let user_registration_domain_service = UserRegistrationDomainService::new(
            user_registration_repository,
            Arc::new(user_repository),
        );
        let user_registration_service = Arc::new(UserRegistrationApplicationService::new(
            user_registration_domain_service,
            email_service,
        ));

        ServiceContainer {
            note_application_service,
            user_registration_service,
        }
    }
}
