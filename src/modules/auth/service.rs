use actix_web::{HttpResponse, web};
use sea_orm::{DbConn, EntityTrait, NotSet, ActiveValue::Set, QueryFilter, ColumnTrait, QueryOrder};
use crate::models::ServiceError;
use crate::modules::auth::controller::NewUserParams;

use chrono;
use actix_http::StatusCode;
use sea_orm::prelude::DateTimeWithTimeZone;
use entity::prelude::User;
use entity::user;

/// Insert user to BD
pub async fn insert_user(
    conn: &DbConn,
    data: &web::Json<NewUserParams>,
) -> Result<HttpResponse, ServiceError> {
    let _ = user::Entity::insert(user::ActiveModel {
        user_id: Set("1".to_string()),
        email: Set("1".to_string()),
        username: Set(data.0.username.to_string()),
        pass_hash: Set("1".to_string()),
        email_validated: Set(true),
        totp_active: Set(true),
        totp_token: NotSet,
        totp_backups: NotSet,
        created_at: Set(DateTimeWithTimeZone::from(chrono::offset::Utc::now())),
        ..Default::default()
    })
        .exec(conn)
        .await
        .map_err (|e| {
           println!("{}", e.to_string());
        });

    Ok(HttpResponse::Ok().body(format!("Hello {}", data.0.username).to_string()))
}

/// Insert user to BD
pub async fn find_user_by_id_from_bd(
    conn: &DbConn,
    data: &web::Json<NewUserParams>,
) -> Result<HttpResponse, ServiceError> {

    let to_find =  data.0.username.to_string();
    let user = User::find()
        .filter(user::Column::Username.contains(&*to_find))
        .one(conn)
        .await
        .unwrap();

    return match user {
        Some(user) => {
           println!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! {}",user.username);

            Ok(HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body("<h1>Ok</h1>"))
        }
        None => {
            Err(ServiceError {
                code: StatusCode::BAD_REQUEST,
                path: "111".to_string(),
                message: "221212".to_string(),
                show_message: false,
            })
        }
    }
}