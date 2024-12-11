use crate::application::dto::shared::universal_response::UniversalResponse;
use crate::application::dto::user::user_authentication_request_dto::{
    APIVerificationMethod, LoginUserRequest, OTPVerificationRequest,
};
use crate::application::dto::user::user_recovery_request_dto::{
    UserCompleteRecoveryRequest, UserRecoveryRequest,
};
use crate::application::dto::user::user_registration_request_dto::{
    CreateUserRequest, ValidateEmailRequest,
};
use crate::application::error::response_error::AppResponseError;
use crate::application::services::service_container::ServiceContainer;
use crate::user_interface::web::actix_adapter::{get_ip_addr, get_user_agent};
use crate::user_interface::web::handlers::auth::auth_request_dto::{
    APIVerificationMethodWeb, ContinueLoginRequestWeb, CreateUserRequestWeb, LoginUserRequestWeb,
    UserCompleteRecoveryRequestWeb, UserRecoveryRequestWeb, ValidateEmailRequestWeb,
};
use actix_web::{web, HttpRequest, HttpResponse};
use std::sync::Arc;

pub async fn create_user(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    params: web::Json<CreateUserRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let user = CreateUserRequest::new(
        params.username.clone(),
        params.email.clone(),
        params.password.clone(),
        params.password_confirm.clone(),
    );

    let saved_user = data
        .user_registration_service
        .create_user(user)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    Ok(HttpResponse::Created().json(saved_user))
}

pub async fn verify_email(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    params: web::Json<ValidateEmailRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let request = ValidateEmailRequest::new(params.email.clone(), params.email_token.clone());

    data.user_registration_service
        .validate_email_user(request)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    let response = UniversalResponse::new("Email verified successfully".to_string(), None, true);
    Ok(HttpResponse::Ok().json(response))
}

pub async fn login(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    params: web::Json<LoginUserRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let user_agent = get_user_agent(&req)?;
    let login_ip = get_ip_addr(&req)?;

    let request = LoginUserRequest::new(
        params.identifier.clone(),
        params.password.clone(),
        user_agent,
        login_ip,
        params.persistent,
    );

    let auth = data
        .user_authentication_service
        .initiate_login(request)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    Ok(HttpResponse::Ok().json(auth))
}

pub async fn login_2fa(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    params: web::Json<ContinueLoginRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let user_agent = get_user_agent(&req)?;
    let login_ip = get_ip_addr(&req)?;

    let verification_method = match &params.verification_method {
        APIVerificationMethodWeb::EmailOTP => APIVerificationMethod::EmailOTP,
        APIVerificationMethodWeb::AuthenticatorApp => APIVerificationMethod::AuthenticatorApp,
    };

    let request = OTPVerificationRequest::new(
        params.public_token.clone(),
        params.code.clone(),
        verification_method,
        user_agent,
        login_ip,
    );

    let auth = data
        .user_authentication_service
        .continue_login(request)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    Ok(HttpResponse::Ok().json(auth))
}

pub async fn forgot_password(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    params: web::Json<UserRecoveryRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let user_agent = get_user_agent(&req)?;
    let login_ip = get_ip_addr(&req)?;

    let request = UserRecoveryRequest::new(params.identifier.clone(), user_agent, login_ip);
    data.user_recovery_service
        .initiate_recovery(request)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    let response = UniversalResponse::new(
        "Password recovery instructions have been sent to your email.".to_string(),
        None,
        true,
    );
    Ok(HttpResponse::Ok().json(response))
}

pub async fn password_reset(
    req: HttpRequest,
    data: web::Data<Arc<ServiceContainer>>,
    params: web::Json<UserCompleteRecoveryRequestWeb>,
) -> Result<HttpResponse, AppResponseError> {
    let user_agent = get_user_agent(&req)?;
    let login_ip = get_ip_addr(&req)?;

    let request = UserCompleteRecoveryRequest::new(
        params.token.clone(),
        params.new_password.clone(),
        params.password_confirm.clone(),
        user_agent,
        login_ip,
    );

    let response = data
        .user_recovery_service
        .complete_recovery(request)
        .await
        .map_err(|e| e.into_service_error(&req))?;

    let response = UniversalResponse::new(response.title, response.subtitle, true);
    Ok(HttpResponse::Ok().json(response))
}
