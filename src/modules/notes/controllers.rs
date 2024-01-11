use crate::models::many_response::PageQuery;
use crate::models::ServiceError;
use crate::modules::auth::middleware::LoginUser;
use crate::modules::notes::models::{DTONote, FindNote};
use crate::modules::notes::service::{
    try_create_note, try_delete_note, try_get_all_notes, try_get_by_id_notes, try_update_note,
};
use actix_web::{web, HttpRequest, HttpResponse};

#[utoipa::path(
    post,
    path = "/api/notes/create",
    request_body = DTONote,
    responses(
         (status = 201, description = "Note created successfully"),
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
    try_create_note(req, &user.id, params.0).await?;
    Ok(HttpResponse::Created().json("Note Create Successfully."))
}

#[utoipa::path(
    get,
    path = "/api/notes/get_all_notes",
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
    let result = try_get_all_notes(req, &user.id, info.0).await?;
    Ok(HttpResponse::Ok().json(result))
}

#[utoipa::path(
    get,
    path = "/api/notes/get_by_id",
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
    let note = try_get_by_id_notes(req, &user.id, query.into_inner()).await?;
    Ok(HttpResponse::Ok().json(note))
}

#[utoipa::path(
    delete,
    path = "/api/notes/delete",
    params(
        FindNote
    ),
    responses(
        (status = 200, description = "Note was deleted"),
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
    try_delete_note(req, &user.id, params.0).await?;
    Ok(HttpResponse::Ok().json("Note was deleted"))
}

#[utoipa::path(
    put,
    path = "/api/notes/update",
    request_body = DTONote,
    params(
        FindNote
    ),
    responses(
         (status = 200, description = "Note was updated"),
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
    try_update_note(req, &user.id, &note_id.id, body.0).await?;
    Ok(HttpResponse::Ok().json("Note was updated"))
}
