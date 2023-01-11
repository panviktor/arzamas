use sea_orm::{ EntityTrait, QueryFilter, ColumnTrait};
use entity::user;
use chrono;

use crate::{err_server, };
use crate::core::db::DB;
use crate::models::{ServerError, User as ModelUser};


/// Get a single user from the DB, searching by username
pub async fn get_user_by_username(username: &str) -> Result<Option<ModelUser>, ServerError> {

    let db = &*DB;

    let to_find =  username.to_string();
    let user = entity::prelude::User::find()
        .filter(user::Column::Username.eq(&*to_find))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem querying database for user {}: {}", username, e));

    match user {
        Ok(user) => {
            match user {
                Some(user) => {
                    let my_struct = ModelUser::from_orm(user);
                    Ok(Option::from(my_struct))
                }
                None => {
                    Ok(None)
                }
            }
        }
        Err(_) => {
            Err(err_server!("Problem querying database for user: cant unwrap ORM"))
        }
    }
}

/// Get a single user from the DB, searching by username
pub async fn get_user_by_email(email: &str) -> Result<Option<ModelUser>, ServerError> {

    let db = &*DB;

    let to_find =  email.to_string();
    let user = entity::prelude::User::find()
        .filter(user::Column::Email.eq(&*to_find))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem querying database for user {}: {}", email, e));

    match user {
        Ok(user) => {
            match user {
                Some(user) => {
                    let my_struct = ModelUser::from_orm(user);
                    Ok(Option::from(my_struct))
                }
                None => {
                    Ok(None)
                }
            }
        }
        Err(_) => {
            Err(err_server!("Problem querying database for user: cant unwrap ORM"))
        }
    }
}

/// Get a single user from the DB searching by user ID
pub async fn get_user_by_userid(user_id: &str)  {

}