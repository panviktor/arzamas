// use actix_web::{web, HttpRequest, HttpResponse};
// use chrono::{DateTime, Utc};
// use deadpool_redis::Pool;
// use entity::user::Model as User;
// use entity::user_otp_token::Model as SecurityToken;
// use entity::user_security_settings::Model as SecuritySettings;
// use entity::{
//     user, user_confirmation, user_otp_token, user_restore_password, user_security_settings,
// };
// use sea_orm::{
//     ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter, Set,
// };
//
// use crate::application::dto::user::user_registration_request_dto::CreateUserRequest;
// use crate::application::error::response_error::AppResponseError;
// use crate::core::constants::core_constants;
// use crate::core::error::{ErrorCode, ServerError};
// use crate::infrastructure::persistence::db::extract_db_connection;
// use crate::modules_deprecated::auth::email::success_enter_email;
// use crate::modules_deprecated::auth::hash_token;
// use crate::{err_input, err_server};
//
// use crate::modules_deprecated::auth::models::{
//     CreatedUserDTO, LoginParams, LoginResponse, UserInfo, VerifyToken,
// };
// use crate::modules_deprecated::auth::session::{
//     generate_session_token, get_ip_addr, get_user_agent,
// };
// use crate::modules_deprecated::auth::totp::{generate_email_code, set_app_only_expire_time};
//
// pub(crate) fn user_created_response(user: &User) -> CreatedUserDTO {
//     CreatedUserDTO {
//         username: user.username.to_string(),
//         creation_day: user.created_at,
//         user_email: user.email.to_string(),
//         description: format!(
//             "Greetings, {}!\n\n\
//         Your account was successfully created on {}.\n\
//         We have dispatched a verification email to: {}.\n\
//         Please follow the instructions in the email to verify your account. \
//         Note that the verification link will remain active for 24 hours only.\n\n\
//         Welcome to our community!\n",
//             user.username, user.created_at, user.email
//         ),
//     }
// }
//
// /// Get a single user from the DB, searching by username
// pub(crate) async fn get_user_by_username(
//     username: &str,
//     db: &DatabaseConnection,
// ) -> Result<Option<User>, ServerError> {
//     let to_find = username.to_string();
//     let user = entity::prelude::User::find()
//         .filter(user::Column::Username.eq(&*to_find))
//         .one(db)
//         .await
//         .map_err(|e| err_server!("Problem querying database for user {}: {}", username, e));
//
//     if let Ok(user) = user {
//         return match user {
//             Some(user) => Ok(Option::from(user)),
//             None => Ok(None),
//         };
//     }
//     Err(err_server!(
//         "Problem querying database for user: cant unwrap ORM"
//     ))
// }
//
// /// Get a single user from the DB, searching by username
// pub async fn get_user_by_email(
//     email: &str,
//     db: &DatabaseConnection,
// ) -> Result<Option<User>, ServerError> {
//     let to_find = email.to_string();
//     let user = entity::prelude::User::find()
//         .filter(user::Column::Email.eq(&*to_find))
//         .one(db)
//         .await
//         .map_err(|e| err_server!("Problem querying database for user {}: {}", email, e));
//
//     if let Ok(user) = user {
//         return match user {
//             Some(user) => Ok(Option::from(user)),
//             None => Ok(None),
//         };
//     }
//     Err(err_server!(
//         "Problem querying database for user: can't unwrap ORM"
//     ))
// }
//
// /// Get a user security settings
// pub(crate) async fn get_user_settings_by_id(
//     user_id: &str,
//     db: &DatabaseConnection,
// ) -> Result<SecuritySettings, ServerError> {
//     let setting_result = entity::prelude::UserSecuritySettings::find()
//         .filter(user_security_settings::Column::UserId.eq(user_id))
//         .one(db)
//         .await;
//
//     match setting_result {
//         Ok(Some(setting)) => Ok(setting),
//         Ok(None) => Err(err_server!(
//             "Problem querying database for user settings: can't unwrap ORM"
//         )),
//         Err(e) => Err(err_server!(
//             "Problem querying database for user {}: {}",
//             user_id,
//             e
//         )),
//     }
// }
//
// /// Get a user security token
// pub async fn get_user_security_token_by_id(
//     user_id: &str,
//     db: &DatabaseConnection,
// ) -> Result<SecurityToken, ServerError> {
//     let token_result = entity::prelude::UserOtpToken::find()
//         .filter(user_otp_token::Column::UserId.eq(user_id))
//         .one(db)
//         .await;
//     return match token_result {
//         Ok(Some(token)) => Ok(token),
//         Ok(None) => {
//             let token = user_otp_token::ActiveModel {
//                 user_id: Set(user_id.to_string()),
//                 ..Default::default()
//             }
//             .insert(db)
//             .await
//             .map_err(|e| err_server!("Problem create OTP token {}:{}", user_id, e))?;
//             Ok(token)
//         }
//         Err(e) => Err(err_server!(
//             "Problem querying database for user {}: {}",
//             user_id,
//             e
//         )),
//     };
// }
//
// /// Get a single user from the DB, searching by username
// pub(crate) async fn get_user_by_id(
//     id: &str,
//     db: &DatabaseConnection,
// ) -> Result<Option<User>, ServerError> {
//     let to_find = id.to_string();
//     let user = entity::prelude::User::find()
//         .filter(user::Column::UserId.eq(&*to_find))
//         .one(db)
//         .await
//         .map_err(|e| err_server!("Problem querying database for user {}: {}", id, e));
//
//     if let Ok(user) = user {
//         return match user {
//             Some(user) => Ok(Option::from(user)),
//             None => Ok(None),
//         };
//     }
//     Err(err_server!(
//         "Problem querying database for user: can't unwrap ORM"
//     ))
// }
//
// pub(crate) async fn add_password_reset_token(
//     user_id: &str,
//     token: &str,
//     expiry: DateTime<Utc>,
//     db: &DatabaseConnection,
// ) -> Result<(), ServerError> {
//     let hashed_token = hash_token(token);
//     // if let Some(user) = user_restore_password::Entity::find()
//     //     .filter(user_restore_password::Column::UserId.contains(user_id))
//     //     .one(db)
//     //     .await
//     //     .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))?
//     // {
//     //     let mut active: user_restore_password::ActiveModel = user.into();
//     //     active.otp_hash = Set(hashed_token.to_string());
//     //     active.expiry = Set(expiry.naive_utc());
//     //     active
//     //         .update(db)
//     //         .await
//     //         .map_err(|e| err_server!("Problem updating restore token {}:{}", user_id, e))?;
//     // } else {
//     //     let new_restore = user_restore_password::ActiveModel {
//     //         user_id: Set(user_id.to_string()),
//     //         otp_hash: Set(hashed_token.to_string()),
//     //         expiry: Set(expiry.naive_utc()),
//     //         ..Default::default()
//     //     };
//     //     new_restore
//     //         .insert(db)
//     //         .await
//     //         .map_err(|e| err_server!("Problem adding restore token {}:{}", user_id, e))?;
//     // }
//
//     Ok(())
// }
//
// pub(crate) async fn verify_password_reset_token(
//     token: &str,
//     db: &DatabaseConnection,
// ) -> Result<UserInfo, ServerError> {
//     let hashed_token = hash_token(token);
//     let user = user_restore_password::Entity::find()
//         .filter(user_restore_password::Column::OtpHash.eq(hashed_token))
//         .one(db)
//         .await
//         .map_err(|e| err_server!("Problem finding password reset token {}: {}", token, e))?
//         .ok_or(err_input!("Token not found."))?;
//
//     let user_id = user.user_id.clone();
//     let user_expiry = user.expiry;
//
//     user.delete(db)
//         .await
//         .map_err(|e| err_server!("Problem delete password reset token {}: {}", token, e))?;
//
//     let now = Utc::now().naive_utc();
//
//     // return if user_expiry > now {
//     //     Ok(UserInfo { user_id })
//     // } else {
//     Err(ServerError {
//         code: ErrorCode::ServerError,
//         message: "Token to restore password not found or expiry".to_string(),
//         show_message: false,
//     })
//     // };
// }
//
// /// Add an email token to the DB
// pub(crate) async fn add_email_token(
//     user_id: &str,
//     email: &str,
//     token: &str,
//     expiry: DateTime<Utc>,
//     user_exists: bool,
//     db: &DatabaseConnection,
// ) -> Result<(), ServerError> {
//     // Uniqueness is taken care of by an index in the DB
//     if !user_exists {
//         let confirmation = user_confirmation::ActiveModel {
//             user_id: Set(user_id.to_string()),
//             email: Set(email.to_string()),
//             // otp_hash: Set(token.to_string()),
//             // expiry: Set(expiry.naive_utc()),
//             ..Default::default()
//         };
//
//         confirmation
//             .insert(db)
//             .await
//             .map_err(|e| err_server!("Problem adding email token {}:{}", user_id, e))?;
//     } else {
//         if let Some(user) = user_confirmation::Entity::find()
//             .filter(user_confirmation::Column::UserId.contains(user_id))
//             .one(db)
//             .await
//             .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))?
//         {
//             let mut active: user_confirmation::ActiveModel = user.into();
//             active.email = Set(email.to_string());
//             // active.otp_hash = Set(token.to_string());
//             // active.expiry = Set(expiry.naive_utc());
//             active
//                 .update(db)
//                 .await
//                 .map_err(|e| err_server!("Problem updating active_user {}:{}", user_id, e))?;
//         }
//     }
//     Ok(())
// }
//
// pub(crate) async fn find_email_verify_token(
//     email: &str,
//     db: &DatabaseConnection,
// ) -> Result<VerifyToken, ServerError> {
//     let confirmation = user_confirmation::Entity::find()
//         .filter(user_confirmation::Column::Email.contains(email))
//         .one(db)
//         .await
//         .map_err(|e| err_server!("Problem finding email and token {}:{}", email, e))?;
//     match confirmation {
//         None => Err(err_server!("Problem finding email and token {}", email)),
//         Some(model) => {
//             let token = VerifyToken {
//                 expiry: model.expiry.clone(),
//                 user_id: model.user_id.clone(),
//                 otp_hash: model.otp_hash.clone(),
//             };
//             model
//                 .delete(db)
//                 .await
//                 .map_err(|e| err_server!("Problem delete token with email: {}:{}", email, e))?;
//             Ok(token)
//         }
//     }
// }
//
// pub(crate) async fn verify_email_by(
//     user_id: &str,
//     db: &DatabaseConnection,
// ) -> Result<(), ServerError> {
//     let user = user::Entity::find()
//         .filter(user::Column::UserId.contains(user_id))
//         .one(db)
//         .await
//         .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))?;
//
//     if user.is_none() {
//         return Err(err_server!("Problem finding user id {}", user_id));
//     }
//
//     let user = user.unwrap();
//     if user.email_validated {
//         return Ok(());
//     }
//
//     let mut item_active_model: user::ActiveModel = user.into();
//     item_active_model.email_validated = Set(true);
//
//     item_active_model
//         .update(db)
//         .await
//         .map_err(|e| err_server!("Problem updating user {}:{}", user_id, e))?;
//     Ok(())
// }
//
// pub(crate) async fn block_user_until(
//     user_id: &str,
//     expiry: DateTime<Utc>,
//     db: &DatabaseConnection,
// ) -> Result<(), ServerError> {
//     if let Some(user) = get_user_by_id(user_id, db)
//         .await
//         .map_err(|e| err_server!("Problem finding user {}:{}", user_id, e))?
//     {
//         let mut active: user::ActiveModel = user.into();
//         active.login_blocked_until = Set(Some(expiry.naive_utc()));
//         active
//             .update(db)
//             .await
//             .map_err(|e| err_server!("Problem updating user {}:{}", user_id, e))?;
//     }
//     Ok(())
// }
//
// pub(crate) async fn set_attempt_count(
//     attempt_count: i32,
//     user_id: &str,
//     mut new_user: user_otp_token::ActiveModel,
//     db: &DatabaseConnection,
// ) -> Result<(), ServerError> {
//     new_user.attempt_count = Set(attempt_count);
//     new_user
//         .update(db)
//         .await
//         .map_err(|e| err_server!("Problem updating OTP token attempt count {}:{}", user_id, e))?;
//     Ok(())
// }
//
// pub(crate) async fn handle_login_result(
//     user_id: &str,
//     user_email: &str,
//     security_settings: SecuritySettings,
//     req: &HttpRequest,
//     params: &LoginParams,
//     db: &DatabaseConnection,
// ) -> Result<HttpResponse, AppResponseError> {
//     let login_ip =
//         get_ip_addr(req).map_err(|s| AppResponseError::general(req, s.message, false))?;
//     let user_agent = get_user_agent(&req);
//     let persistent = params.persist.unwrap_or(false);
//
//     let redis_pool = req
//         .app_data::<web::Data<Pool>>() // Make sure Pool is the type of your Redis connection pool
//         .ok_or_else(|| AppResponseError::general(&req, "Failed to extract Redis pool", true))?;
//
//     return match (
//         security_settings.two_factor_email,
//         security_settings.two_factor_authenticator_app,
//     ) {
//         (true, true) => {
//             generate_email_code(user_id, persistent, user_email, &login_ip, &user_agent, db)
//                 .await
//                 .map_err(|s| AppResponseError::general(&req, s.message, false))?;
//             let json = LoginResponse::OTPResponse {
//                 message: "The code has been sent to your email!\n
//                 Enter your code from email and code from 2FA apps like Google Authenticator and Authy!
//                 "
//                     .to_string(),
//                 apps_code: true,
//                 id: None,
//             };
//             Ok(HttpResponse::Ok().json(json))
//         }
//         (true, false) => {
//             generate_email_code(user_id, persistent, user_email, &login_ip, &user_agent, db)
//                 .await
//                 .map_err(|s| AppResponseError::general(&req, s.message, false))?;
//             let json = LoginResponse::OTPResponse {
//                 message: "The code has been sent to your email!".to_string(),
//                 apps_code: false,
//                 id: None,
//             };
//             Ok(HttpResponse::Ok().json(json))
//         }
//         (false, true) => {
//             set_app_only_expire_time(user_id, persistent, &login_ip, &user_agent, db)
//                 .await
//                 .map_err(|s| AppResponseError::general(&req, s.message, false))?;
//             let json = LoginResponse::OTPResponse {
//                 message: "Enter your OTP code! For better security, use dual authorization in conjunction with email.".to_string(),
//                 apps_code: true,
//                 id: Some(user_id.to_string()),
//             };
//             Ok(HttpResponse::Ok().json(json))
//         }
//         (false, false) => {
//             let token =
//                 generate_session_token(user_id, persistent, &login_ip, &user_agent, redis_pool)
//                     .await
//                     .map_err(|s| AppResponseError::general(&req, s.message, false))?;
//
//             if security_settings.email_on_success_enabled_at {
//                 success_enter_email(user_email, &login_ip)
//                     .await
//                     .map_err(|s| AppResponseError::general(&req, s.message, false))?;
//             }
//
//             let response = LoginResponse::TokenResponse {
//                 token,
//                 token_type: core_constants::BEARER.to_string(),
//             };
//             Ok(HttpResponse::Ok().json(response))
//         }
//     };
// }
