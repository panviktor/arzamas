use crate::models::ServiceError;
use actix_web::{web, HttpRequest, HttpResponse};

use crate::modules::auth::email::verify_user_email;
use crate::modules::auth::models::{
    ForgotPasswordParams, LoginParams, NewUserParams, OTPCode, ResetPasswordParams,
    VerifyEmailParams,
};
use crate::modules::auth::service::{
    try_create_user, try_login_2fa, try_login_user, try_reset_password, try_send_restore_email,
};

/// Creates a new user.
///
/// This asynchronous function is responsible for handling the creation of a new user. It takes in the
/// HTTP request and the parameters for the new user, validates the data, and attempts to create a new user record.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request.
/// * `params` - The parameters for creating a new user, wrapped in `web::Json` for automatic deserialization from the request body.
///
/// # Responses
/// * `201 Created` - Returned if the user is created successfully. The response body includes the details of the created user.
/// * `400 Bad Request` - Returned if the input data for the new user is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited due to too many requests.
/// * `500 Internal Server Error` - Returned if an unexpected error occurs during the process.
///
/// # Examples
/// ```
/// // Example of a POST request to /auth/create with valid user data.
/// ```
///
/// # Errors
/// This function returns an error (`ServiceError`) if the user creation process fails at any point, including validation failures,
/// rate-limiting issues, or internal server errors.
///
#[utoipa::path(
    post,
    path = "/api/auth/create",
    request_body = NewUserParams,
    responses(
         (status = 201, description = "User created successfully"),
         (status = 400, description = "User data invalid"),
         (status = 429, description = "Too Many Requests"),
         (status = 500, description = "Internal Server Error")
    )
)]
pub async fn create_user(
    req: HttpRequest,
    params: web::Json<NewUserParams>,
) -> Result<HttpResponse, ServiceError> {
    let saved_user = try_create_user(&req, params.0).await?;
    Ok(HttpResponse::Created().json(saved_user))
}

pub async fn verify_email(
    req: HttpRequest,
    params: web::Json<VerifyEmailParams>,
) -> Result<HttpResponse, ServiceError> {
    verify_user_email(&params.email, &params.email_token)
        .await
        .map_err(|s| s.general(&req))?;
    Ok(HttpResponse::Ok().finish())
}

pub async fn login(
    req: HttpRequest,
    params: web::Json<LoginParams>,
) -> Result<HttpResponse, ServiceError> {
    try_login_user(&req, params.0).await
}

pub async fn login_2fa(
    req: HttpRequest,
    params: web::Json<OTPCode>,
) -> Result<HttpResponse, ServiceError> {
    let json_response = try_login_2fa(&req, params.0).await?;
    Ok(HttpResponse::Ok().json(json_response))
}

pub async fn forgot_password(
    req: HttpRequest,
    params: web::Json<ForgotPasswordParams>,
) -> Result<HttpResponse, ServiceError> {
    try_send_restore_email(&req, params.0).await?;
    Ok(HttpResponse::Ok().json("A password reset request has been sent."))
}

pub async fn password_reset(
    req: HttpRequest,
    params: web::Json<ResetPasswordParams>,
) -> Result<HttpResponse, ServiceError> {
    try_reset_password(&req, params.0).await?;
    Ok(HttpResponse::Ok().json("Password successfully reset."))
}
