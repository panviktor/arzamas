use crate::application::services::note::service::{
    try_create_note, try_delete_note, try_get_all_notes, try_get_by_id_notes, try_update_note,
};
use crate::infrastructure::web::notes::dto_models::{DTONote, FindNote};
use crate::models::many_response::{PageQuery, UniversalResponse};
use crate::application::error::service_error::ServiceError;
use crate::modules::auth::middleware::LoginUser;
use actix_web::{web, HttpRequest, HttpResponse};

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
request_body = DTONote,
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
    user: LoginUser,
    params: web::Json<DTONote>,
) -> Result<HttpResponse, ServiceError> {
    try_create_note(&req, &user.id, params.0).await?;
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
(status = 200, description = "Note information retrieved successfully", body = ManyResponseNotes),
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
    info: web::Query<PageQuery>,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    let result = try_get_all_notes(&req, &user.id, info.0).await?;
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
    user: LoginUser,
    query: web::Query<FindNote>,
) -> Result<HttpResponse, ServiceError> {
    let note = try_get_by_id_notes(&req, &user.id, query.into_inner()).await?;
    Ok(HttpResponse::Ok().json(note))
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
FindNote
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
    user: LoginUser,
    params: web::Query<FindNote>,
) -> Result<HttpResponse, ServiceError> {
    try_delete_note(&req, &user.id, params.0).await?;
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
request_body = DTONote,
params(
FindNote
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
    user: LoginUser,
    note_id: web::Query<FindNote>,
    body: web::Json<DTONote>,
) -> Result<HttpResponse, ServiceError> {
    try_update_note(&req, &user.id, &note_id.id, body.0).await?;
    let response = UniversalResponse::new("Note was updated.".to_string(), None, true);
    Ok(HttpResponse::Ok().json(response))
}
