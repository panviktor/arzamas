use crate::models::many_response::PageQuery;
use crate::models::ServiceError;
use crate::modules::auth::middleware::LoginUser;
use crate::modules::notes::service::{
    try_create_note, try_delete_note, try_get_all_notes, try_get_by_id_notes, try_update_note,
    CreateNote, DTONote, FindNote,
};
use actix_web::{web, HttpRequest, HttpResponse};

pub async fn create_note(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<DTONote>,
) -> Result<HttpResponse, ServiceError> {
    try_create_note(req, &user.id, params.0).await?;
    Ok(HttpResponse::Ok().json("Note Create Successfully."))
}

pub async fn get_all_notes(
    req: HttpRequest,
    info: web::Query<PageQuery>,
    user: LoginUser,
) -> Result<HttpResponse, ServiceError> {
    let result = try_get_all_notes(req, &user.id, info.0).await?;
    Ok(HttpResponse::Ok().json(result))
}

pub async fn get_by_id(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<FindNote>,
) -> Result<HttpResponse, ServiceError> {
    let note = try_get_by_id_notes(req, &user.id, params.0).await?;
    Ok(HttpResponse::Ok().json(note))
}

pub async fn delete(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<FindNote>,
) -> Result<HttpResponse, ServiceError> {
    try_delete_note(req, &user.id, params.0).await?;
    Ok(HttpResponse::Ok().json("Note was deleted"))
}

pub async fn update(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<CreateNote>,
) -> Result<HttpResponse, ServiceError> {
    try_update_note(req, &user.id, params.0).await?;
    Ok(HttpResponse::Ok().json("Note was updated"))
}
