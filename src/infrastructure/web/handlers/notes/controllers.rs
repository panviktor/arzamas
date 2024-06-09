use crate::application::dto::note::note_request_dto::{
    CreateNoteRequest, GetAllNotesRequest, NoteByIdRequest, UpdateNoteRequest,
};
use crate::application::dto::shared::page_query::PageQuery;
use crate::application::dto::shared::universal_response::UniversalResponse;
use crate::application::error::response_error::AppResponseError;
use crate::application::services::service_container::ServiceContainer;
use crate::infrastructure::web::dto::shared::LoginUser;
use crate::infrastructure::web::handlers::notes::note_request_dto::{
    NoteIdRequestWeb, NoteRequestWeb,
};
use actix_web::{web, HttpRequest, HttpResponse};
use std::sync::Arc;

/// Creates a new note.
///
/// This function takes a `HttpRequest`, `LoginUser`, and `DTONote` as input
/// and attempts to create a new note in the system.
///
/// # Arguments
/// * `req` - The HTTP request information.
/// * `user` - The logged-in user information.
/// * `params` - The note data to be created.
///
/// # Returns
/// This function returns a `Result` which is either an `HttpResponse` indicating
/// successful creation of the note, or a `ServiceError` in case of failure.
#[utoipa::path(
    post,
    path = "/api/note/create",
    request_body = CreateNoteRequestWeb,
    responses(
        (status = 201, description = "Note created successfully", body = UniversalResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests")
    ),
    security(
    ("token" = [])
    )
)]
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

/// Retrieves all note.
///
/// This function is an API endpoint for fetching all note available to the logged-in user.
/// It takes an HTTP request, pagination query parameters, and the logged-in user's details as input.
///
/// The API responds with an HTTP response. If the note are retrieved successfully,
/// it returns a 200 status code with the note' data. If the retrieval fails,
/// it returns an appropriate error message and status code, such as 401 for unauthorized access
/// or 404 for not found.
///
/// # Arguments
/// * `req` - The HTTP request information.
/// * `info` - The pagination query parameters.
/// * `user` - The logged-in user information.
///
/// # Returns
/// This function returns a `Result` which is either an `HttpResponse` with the note data,
/// or a `ServiceError` in case of failure.
#[utoipa::path(
    get,
    path = "/api/note/get_all_notes",
    params(
        PageQuery
    ),
    responses(
        (status = 200, description = "Note information retrieved successfully", body = PaginatedResultNotes),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found", body = ServiceErrorSerialized),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
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

/// Retrieves a note by its ID.
///
/// This function is an API endpoint for fetching a specific note by its unique identifier.
/// It requires the note's ID, the HTTP request information, and the logged-in user's details.
///
/// The API responds with an HTTP response. If the note is found, it returns a 200 status code with
/// the note data. If the note is not found or an error occurs, it returns an appropriate error
/// message and status code.
///
/// # Arguments
/// * `req` - The HTTP request information.
/// * `user` - The logged-in user information.
/// * `query` - The query parameters containing the note's ID.
///
/// # Returns
/// This function returns a `Result` which is either an `HttpResponse` with the note data,
/// or a `ServiceError` in case of failure.
#[utoipa::path(
    get,
    path = "/api/note/get_by_id",
    params(
        ("id" = i64, Query, description = "Unique identifier of the note")
    ),
    responses(
        (status = 200, description = "Note information retrieved successfully", body = Note),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found", body = ServiceErrorSerialized),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
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

/// Deletes a note.
///
/// This function is an API endpoint for deleting a specific note identified by the provided parameters.
/// It requires the note's identifying information, the HTTP request, and the logged-in user's details.
///
/// The API responds with an HTTP response. If the note is deleted successfully, it returns a 200 status
/// code with a success message. If the deletion fails, it returns an appropriate error message and status code.
///
/// # Arguments
/// * `req` - The HTTP request information.
/// * `user` - The logged-in user information.
/// * `params` - The query parameters identifying the note to be deleted.
///
/// # Returns
/// This function returns a `Result` which is either an `HttpResponse` confirming the deletion,
/// or a `ServiceError` in case of failure.
#[utoipa::path(
    delete,
    path = "/api/note/delete",
    params(
        NoteIdRequestWeb
    ),
    responses(
        (status = 200, description = "Note was deleted", body = UniversalResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found", body = ServiceErrorSerialized),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
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

/// Updates a note.
///
/// This function is an API endpoint for updating an existing note.
/// It takes the note's ID, new data for the note, the HTTP request, and the logged-in user's details.
///
/// The API responds with an HTTP response. If the update is successful, it returns a 200 status code
/// with a success message. If the update fails, it returns an appropriate error message and status code.
///
/// # Arguments
/// * `req` - The HTTP request information.
/// * `user` - The logged-in user information.
/// * `note_id` - The query parameters containing the ID of the note to be updated.
/// * `body` - The new data for the note.
///
/// # Returns
/// This function returns a `Result` which is either an `HttpResponse` confirming the update,
/// or a `ServiceError` in case of failure.
#[utoipa::path(
    put,
    path = "/api/note/update",
    request_body = NoteRequestWeb,
        params(
            NoteIdRequestWeb
    ),
    responses(
        (status = 200, description = "Note was updated", body = UniversalResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests")
    ),
    security(
        ("token" = [])
    )
)]
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
