use crate::application::dto::note::note_request_dto::{
    CreateNoteRequest, GetAllNotesRequest, NoteByIdRequest, UpdateNoteRequest,
};
use crate::application::dto::shared::page_query::PageQuery;
use crate::application::dto::shared::universal_response::UniversalResponse;
use crate::application::error::response_error::AppResponseError;
use crate::application::services::service_container::ServiceContainer;
use crate::user_interface::web::dto::shared::LoginUser;
use crate::user_interface::web::handlers::notes::note_request_dto::{
    NoteIdRequestWeb, NoteRequestWeb,
};
use actix_web::{web, HttpRequest, HttpResponse};
use std::sync::Arc;

pub async fn create_note(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
    params: web::Json<NoteRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let note = CreateNoteRequest::new(&user.id, &params.text);
    let _ = data
        .note_service
        .create_note(note)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    let response = UniversalResponse::new("Note Create Successfully.".to_string(), None, true);
    Ok(HttpResponse::Created().json(response))
}

pub async fn get_all_notes(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    query: web::Query<PageQuery>,
    user: LoginUser,
) -> Result<HttpResponse, AppResponseError> {
    let request = GetAllNotesRequest::new(&user.id, query.page, query.per_page);

    let result = data
        .note_service
        .get_all_notes(request)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    Ok(HttpResponse::Ok().json(result))
}

pub async fn get_by_id(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
    query: web::Query<NoteIdRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let request = NoteByIdRequest::new(&user.id, &query.id);
    let result = data
        .note_service
        .get_note_by_id(request)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    Ok(HttpResponse::Ok().json(result))
}

pub async fn delete(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
    query: web::Query<NoteIdRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let request = NoteByIdRequest::new(&user.id, &query.id);
    data.note_service
        .delete_note(request)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    let response = UniversalResponse::new("Note was deleted.".to_string(), None, true);
    Ok(HttpResponse::Ok().json(response))
}

pub async fn update(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
    note_id: web::Query<NoteIdRequestWeb>,
    body: web::Json<NoteRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let request = UpdateNoteRequest::new(&user.id, &note_id.id, &body.text);
    data.note_service
        .update_note(request)
        .await
        .map_err(|e| e.into_service_error(&req))?;
    let response = UniversalResponse::new("Note was updated.".to_string(), None, true);
    Ok(HttpResponse::Ok().json(response))
}
