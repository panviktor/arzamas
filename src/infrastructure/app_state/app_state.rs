use crate::application::services::note::service::NoteService;
use crate::infrastructure::repository::note::seaorm_note_repository::SeaOrmNoteRepository;

pub(crate) struct AppState {
    pub(crate) note_service: NoteService<SeaOrmNoteRepository>,
}
