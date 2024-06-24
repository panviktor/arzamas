use crate::application::dto::shared::universal_response::UniversalResponse;
use crate::application::dto::user::user_security_request_dto::{
    ActivateEmail2FARequest, ChangeEmailRequest, ChangePasswordRequest, ConfirmDeleteUserRequest,
    ConfirmEmail2FARequest, ConfirmEmailRequest, SecuritySettingsUpdateRequest,
};
use crate::application::dto::user::user_shared_request_dto::UserByIdRequest;
use crate::application::dto::user::user_shared_response_dto::UniversalApplicationResponse;
use crate::application::error::response_error::AppResponseError;
use crate::application::services::service_container::ServiceContainer;
use crate::user_interface::web::actix_adapter::actix_adapter::extract_session_token_from_request;
use crate::user_interface::web::dto::shared::LoginUser;
use crate::user_interface::web::handlers::user::user_request_dto::{
    ActivateEmail2FARequestWeb, ChangeEmailRequestWeb, ChangePasswordRequestWeb,
    ConfirmDeleteUserWeb, ConfirmEmail2FARequestWeb, ConfirmEmailRequestWeb,
    SecuritySettingsUpdateRequestWeb,
};
use crate::user_interface::web::handlers::user::user_response_dto::{
    BaseUserResponseWeb, SecuritySettingsResponseWeb, UserSessionResponseWeb,
};
use actix_web::{web, HttpRequest, HttpResponse};
use std::sync::Arc;

pub async fn about_me(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
) -> Result<HttpResponse, AppResponseError> {
    let request = UserByIdRequest::new(&user.id);
    let response: BaseUserResponseWeb = data
        .user_information_service
        .get_user_information(request)
        .await
        .map_err(|e| e.into_service_error(&req))?
        .into();

    Ok(HttpResponse::Ok().json(response))
}

pub async fn logout(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
) -> Result<HttpResponse, AppResponseError> {
    let user = UserByIdRequest::new(&user.id);
    let current_session = extract_session_token_from_request(&req)?;
    let response = data
        .user_security_service
        .logout_current_session(user, &current_session)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}

pub async fn logout_all(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
) -> Result<HttpResponse, AppResponseError> {
    let user = UserByIdRequest::new(&user.id);
    let response = data
        .user_security_service
        .logout_all_sessions(user)
        .await
        .map_err(|e| e.into_service_error(&req))?;
    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}

pub async fn current_session(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
) -> Result<HttpResponse, AppResponseError> {
    let user = UserByIdRequest::new(&user.id);
    let current_session = extract_session_token_from_request(&req)?;

    let response: UserSessionResponseWeb = data
        .user_security_service
        .get_user_session(user, &current_session)
        .await
        .map_err(|e| e.into_service_error(&req))?
        .into();

    Ok(HttpResponse::Ok().json(response))
}

pub async fn all_sessions(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
) -> Result<HttpResponse, AppResponseError> {
    let user = UserByIdRequest::new(&user.id);

    let response: Vec<UserSessionResponseWeb> = data
        .user_security_service
        .get_user_sessions(user)
        .await
        .map_err(|e| e.into_service_error(&req))?
        .into_iter()
        .map(UserSessionResponseWeb::from)
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

pub async fn change_password(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
    params: web::Json<ChangePasswordRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let application_request = ChangePasswordRequest::new(
        user.id,
        params.current_password.to_string(),
        params.new_password.to_string(),
        params.new_password_confirm.to_string(),
    );

    let response = data
        .user_security_service
        .change_password(application_request)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}

pub async fn change_email(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
    params: web::Json<ChangeEmailRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let application_request = ChangeEmailRequest::new(
        user.id,
        params.new_email.to_string(),
        params.new_email_confirm.to_string(),
    );

    let response = data
        .user_security_service
        .change_email(application_request)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}
pub async fn cancel_email_change(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
) -> Result<HttpResponse, AppResponseError> {
    let user = UserByIdRequest::new(&user.id);
    let response = data
        .user_security_service
        .cancel_email_change(user)
        .await
        .map_err(|e| e.into_service_error(&req))?;
    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}

pub async fn confirm_email(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
    params: web::Json<ConfirmEmailRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let application_request = ConfirmEmailRequest::new(user.id, params.email_token.to_string());

    let response = data
        .user_security_service
        .confirm_email(application_request)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}

pub async fn get_security_settings(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
) -> Result<HttpResponse, AppResponseError> {
    let user = UserByIdRequest::new(&user.id);
    let response: SecuritySettingsResponseWeb = data
        .user_security_service
        .get_security_settings(user)
        .await
        .map_err(|e| e.into_service_error(&req))?
        .into();

    Ok(HttpResponse::Ok().json(response))
}

pub async fn update_security_settings(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
    params: web::Json<SecuritySettingsUpdateRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let application_request = SecuritySettingsUpdateRequest::new(
        user.id,
        params.email_on_success,
        params.email_on_failure,
        params.close_sessions_on_change_password,
    );
    let response: UniversalApplicationResponse = data
        .user_security_service
        .update_security_settings(application_request)
        .await
        .map_err(|e| e.into_service_error(&req))?
        .into();

    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}

///Email 2FA Block
pub async fn enable_email_2fa(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
    params: web::Json<ActivateEmail2FARequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let application_request = ActivateEmail2FARequest::new(user.id, params.email.to_string());
    let response: UniversalApplicationResponse = data
        .user_security_service
        .enable_email_2fa(application_request)
        .await
        .map_err(|e| e.into_service_error(&req))?
        .into();

    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}

pub async fn confirm_email_2fa(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
    params: web::Json<ConfirmEmail2FARequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let application_request = ConfirmEmail2FARequest::new(user.id, params.token.to_string());
    let response: UniversalApplicationResponse = data
        .user_security_service
        .confirm_email_2fa(application_request)
        .await
        .map_err(|e| e.into_service_error(&req))?
        .into();

    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}

pub async fn disable_email_2fa(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
) -> Result<HttpResponse, AppResponseError> {
    let user = UserByIdRequest::new(&user.id);
    let response: UniversalApplicationResponse = data
        .user_security_service
        .disable_email_2fa(user)
        .await
        .map_err(|e| e.into_service_error(&req))?
        .into();

    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}

pub async fn confirm_disable_email_2fa(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
    params: web::Json<ConfirmEmail2FARequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let application_request = ConfirmEmail2FARequest::new(user.id, params.token.to_string());
    let response: UniversalApplicationResponse = data
        .user_security_service
        .confirm_disable_email_2fa(application_request)
        .await
        .map_err(|e| e.into_service_error(&req))?
        .into();

    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}

/// App 2FA Block

pub async fn enable_app_2fa(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
) -> Result<HttpResponse, AppResponseError> {
    // let json = try_2fa_add(&req, &user.id).await?;
    // Ok(HttpResponse::Ok().json(json))
    todo!()
}

pub async fn verify_app_2fa(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
    // params: web::Json<MnemonicConfirmation>,
) -> Result<HttpResponse, AppResponseError> {
    // try_2fa_activate(&req, &user.id, params.0).await?;
    // let response = UniversalResponse::new(
    //     "2FA Successfully Activated".to_string(),
    //     Some(
    //         "Congratulations on successfully setting up two-factor authentication (2FA) for your account!\
    //          This additional layer of security will help protect your account and ensure that only authorized individuals can access it.\
    //          Remember to keep your 2FA device or app safe and secure.".to_string()
    //     ),
    //     true,
    // );
    // Ok(HttpResponse::Ok().json(response))
    todo!()
}

pub async fn reset_app_2fa(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
) -> Result<HttpResponse, AppResponseError> {
    // let json = try_2fa_reset(&req, &user.id).await?;
    // Ok(HttpResponse::Ok().json(json))
    todo!()
}

pub async fn remove_app_2fa(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
) -> Result<HttpResponse, AppResponseError> {
    // try_2fa_remove(&req, &user.id).await?;
    // let response = UniversalResponse::new(
    //     "2FA Successfully Removed".to_string(),
    //     Some("Please keep in mind that disabling two-factor authentication (2FA) reduces the security of your account.\
    //     It is recommended to use alternative security measures such as strong passwords,\
    //     regular account monitoring,\
    //     and enabling other security features provided by the platform to maintain the security of your account.".to_string()),
    //     true,
    // );
    // Ok(HttpResponse::Ok().json(response))
    todo!()
}

pub async fn initiate_delete_user(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
) -> Result<HttpResponse, AppResponseError> {
    let request = UserByIdRequest::new(&user.id);
    let response: UniversalApplicationResponse = data
        .user_security_service
        .initiate_delete_user(request)
        .await
        .map_err(|e| e.into_service_error(&req))?
        .into();

    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}

pub async fn confirm_delete_user(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    user: LoginUser,
    params: web::Json<ConfirmDeleteUserWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let application_request = ConfirmDeleteUserRequest::new(user.id, params.token.to_string());
    let response = data
        .user_security_service
        .confirm_delete_user(application_request)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}
