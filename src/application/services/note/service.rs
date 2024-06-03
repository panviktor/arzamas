use crate::application::dto::note::note_request_dto::{
    CreateNoteRequest, GetAllNotesRequest, NoteByIdRequest, UpdateNoteRequest,
};
use crate::application::dto::note::note_response_dto::NoteResponse;
use crate::application::dto::shared::paginated_result::PaginatedResult;
use crate::application::error::error::ApplicationError;
use crate::domain::entities::note::NoteText;
use crate::domain::ports::repositories::note::note_parameters::{
    CreateNoteDTO, FindNoteDTO, FindNotesDTO, UpdateNoteDTO,
};
use crate::domain::ports::repositories::note::note_repository::NoteDomainRepository;
use crate::domain::services::note::note_service::NoteDomainService;
use std::cmp::{max, min};

pub struct NoteApplicationService<R: NoteDomainRepository> {
    note_domain_service: NoteDomainService<R>,
}

impl<R: NoteDomainRepository> NoteApplicationService<R> {
    pub fn new(note_domain_service: NoteDomainService<R>) -> Self {
        Self {
            note_domain_service,
        }
    }
    pub async fn create_note(
        &self,
        dto_note: CreateNoteRequest,
    ) -> Result<NoteResponse, ApplicationError> {
        let note_text = NoteText(dto_note.text);
        let note_dto = CreateNoteDTO::new(dto_note.user_id, note_text);
        let created_note = self.note_domain_service.add_note(note_dto).await?;
        Ok(NoteResponse::from(created_note))
    }

    pub async fn get_all_notes(
        &self,
        request: GetAllNotesRequest,
    ) -> Result<PaginatedResult<NoteResponse>, ApplicationError> {
        let per_page = max(min(request.per_page, 100), 1);

        let find_notes = FindNotesDTO {
            user_id: request.user_id,
            page: request.page,
            per_page,
        };

        let paginated_notes = self.note_domain_service.find_all(find_notes).await?;
        let note_responses: Vec<NoteResponse> = paginated_notes
            .items
            .into_iter()
            .map(|note| NoteResponse::from(note))
            .collect();

        Ok(PaginatedResult {
            items: note_responses,
            total_items: paginated_notes.total_items,
            total_pages: paginated_notes.total_pages,
            current_page: request.page,
            items_per_page: per_page,
        })
    }

    pub async fn get_note_by_id(
        &self,
        request: NoteByIdRequest,
    ) -> Result<NoteResponse, ApplicationError> {
        let find_note = FindNoteDTO {
            user_id: request.user_id,
            note_id: request.note_id,
        };
        let found_note = self.note_domain_service.find_one(find_note).await?;
        Ok(NoteResponse::from(found_note))
    }

    pub async fn delete_note(&self, request: NoteByIdRequest) -> Result<(), ApplicationError> {
        let find_note = FindNoteDTO {
            user_id: request.user_id,
            note_id: request.note_id,
        };
        self.note_domain_service.delete(find_note).await?;
        Ok(())
    }

    pub async fn update_note(
        &self,
        request: UpdateNoteRequest,
    ) -> Result<NoteResponse, ApplicationError> {
        let update_note = UpdateNoteDTO {
            user_id: request.user_id,
            note_id: request.note_id,
            text: NoteText(request.text),
        };
        let updated_note = self.note_domain_service.update(update_note).await?;
        Ok(NoteResponse::from(updated_note))
    }
}
