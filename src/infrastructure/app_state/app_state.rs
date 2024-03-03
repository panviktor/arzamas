use crate::infrastructure::repository::note::seaorm_note_repository::SeaOrmNoteRepository;

pub(crate) struct AppState {
    pub note_service: SeaOrmNoteRepository,
}
