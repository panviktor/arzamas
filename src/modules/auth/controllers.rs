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
/// This function is responsible for handling the creation of a new user. It takes in the
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
         (status = 201, description = "User created successfully", body = CreatedUserDTO),
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

/// Verifies a user's email.
///
/// This function is responsible for handling the verification of a user's email.
/// It takes in the HTTP request and parameters for email verification, which includes the user's email
/// and a verification token, and attempts to verify the email.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request.
/// * `params` - The parameters for email verification, wrapped in `web::Json` for automatic deserialization from the request body.
///
/// # Responses
/// * `200 OK` - Returned if the email is verified successfully.
/// * `400 Bad Request` - Returned if the input data for email verification is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited due to too many requests.
/// * `500 Internal Server Error` - Returned if an unexpected error occurs during the verification process.
///
/// # Examples
/// ```
/// // Example of a POST request to /api/auth/verify_email with valid email verification data.
/// ```
///
/// # Errors
/// This function returns an error (`ServiceError`) if the email verification process fails at any point,
/// including validation failures, rate-limiting issues, or internal server errors.
///
#[utoipa::path(
    post,
    path = "/api/auth/verify-email",
    request_body = VerifyEmailParams,
    responses(
         (status = 200, description = "Email verified successfully"),
         (status = 400, description = "Verification data invalid"),
         (status = 429, description = "Too Many Requests"),
         (status = 500, description = "Internal Server Error")
    )
)]
pub async fn verify_email(
    req: HttpRequest,
    params: web::Json<VerifyEmailParams>,
) -> Result<HttpResponse, ServiceError> {
    verify_user_email(&params.email, &params.email_token)
        .await
        .map_err(|s| s.general(&req))?;
    Ok(HttpResponse::Ok().finish())
}

/// Logs in a user.
///
/// This function is responsible for handling the login process of a user. It takes in the
/// HTTP request and login parameters, validates the provided credentials (username/email and password),
/// and performs the necessary authentication logic. Depending on the user's security settings,
/// this may involve sending an OTP code via email, generating a token, or other authentication methods.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request.
/// * `params` - The login parameters, wrapped in `web::Json` for automatic deserialization from the request body.
///
/// # Responses
/// * `200 OK` - Returned if the login is successful. The response body includes either a `TokenResponse` with the session token
/// or an `OTPResponse` indicating the need for further authentication steps.
/// * `401 Unauthorized` - Returned if the credentials are invalid or if the login is otherwise unauthorized.
/// * `429 Too Many Requests` - Returned if the request is rate-limited due to too many attempts.
/// * `500 Internal Server Error` - Returned if an unexpected error occurs during the login process.
///
/// # Examples
/// ```
/// // Example of a POST request to /api/auth/login with valid login data.
/// ```
///
/// # Errors
/// This function returns an error (`ServiceError`) if the login process fails at any stage,
/// including validation failures, rate-limiting issues, or internal server errors.
///
#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginParams,
    responses(
         (status = 200, description = "User login successfully", body = LoginResponse),
         (status = 400, description = "User data invalid"),
         (status = 401, description = "Unauthorized", body = ServiceErrorSerialized),
         (status = 429, description = "Too Many Requests"),
         (status = 500, description = "Internal Server Error")
    )
)]
pub async fn login(
    req: HttpRequest,
    params: web::Json<LoginParams>,
) -> Result<HttpResponse, ServiceError> {
    try_login_user(&req, params.0).await
}

/// Logs in a user with 2-Factor Authentication (2FA).
///
/// This function is responsible for handling the 2FA part of the user login process.
/// It validates the one-time password (OTP) codes provided by the user, which can include codes
/// from an email and/or an authenticator app. The function then attempts to verify these codes
/// against the user's account settings and stored OTP tokens.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request.
/// * `params` - The OTP codes for 2FA, wrapped in `web::Json` for automatic deserialization from the request body.
///
/// # Responses
/// * `200 OK` - Returned if the 2FA verification is successful. The response body includes a `TokenResponse` with the session token.
/// * `400 Bad Request` - Returned if the provided OTP codes are invalid.
/// * `429 Too Many Requests` - Returned if there are too many failed attempts, indicating rate-limiting.
/// * `500 Internal Server Error` - Returned if an unexpected error occurs during the verification process.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the 2FA verification process fails,
/// including cases such as invalid OTP codes, rate-limiting, or internal server errors.
///
#[utoipa::path(
    post,
    path = "/api/auth/login-2fa",
    request_body = OTPCode,
    responses(
         (status = 200, description = "User login successfully", body = LoginResponse),
         (status = 400, description = "User data invalid"),
         (status = 429, description = "Too Many Requests"),
         (status = 500, description = "Internal Server Error")
    )
)]
pub async fn login_2fa(
    req: HttpRequest,
    params: web::Json<OTPCode>,
) -> Result<HttpResponse, ServiceError> {
    let json_response = try_login_2fa(&req, params.0).await?;
    Ok(HttpResponse::Ok().json(json_response))
}

/// Initiates a password reset process for a user.
///
/// This function handles the process of initiating a password reset when a user has
/// forgotten their password. It takes in an HTTP request along with the user's username and email
/// (wrapped in `ForgotPasswordParams`), validates this information, and sends a password reset email
/// if the provided details are correct and match an existing user.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request.
/// * `params` - The username and email of the user, wrapped in `web::Json` for automatic deserialization from the request body.
///
/// # Responses
/// * `200 OK` - Returned if a password reset request is successfully initiated. The response body includes a confirmation message.
/// * `400 Bad Request` - Returned if the provided data (username or email) is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited due to too many attempts.
/// * `500 Internal Server Error` - Returned if an unexpected error occurs during the process.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the password reset process fails at any point,
/// including validation failures, issues in sending the reset email, or internal server errors.
///
#[utoipa::path(
    post,
    path = "/api/auth/forgot-password",
    request_body = ForgotPasswordParams,
    responses(
         (status = 200, description = "User created successfully"),
         (status = 400, description = "User data invalid"),
         (status = 429, description = "Too Many Requests"),
         (status = 500, description = "Internal Server Error")
    )
)]
pub async fn forgot_password(
    req: HttpRequest,
    params: web::Json<ForgotPasswordParams>,
) -> Result<HttpResponse, ServiceError> {
    try_send_restore_email(&req, params.0).await?;
    Ok(HttpResponse::Ok().json("A password reset request has been sent."))
}

/// Handles the password reset process for a user.
///
/// This function is responsible for resetting a user's password. It receives an HTTP request
/// containing the password reset token and the new password details, verifies the token, checks the validity
/// of the new password, and updates the user's password if all checks pass.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request.
/// * `params` - The password reset parameters, including the reset token and new password details, wrapped in `web::Json`.
///   - `user_id`: The unique identifier of the user for whom the password is being reset.
///   - `token`: The password reset token that verifies the user's identity and the validity of the reset request.
///   - `password`: The new password chosen by the user.
///   - `password_confirm`: Confirmation of the new password for verification purposes.
///
/// # Responses
/// * `200 OK` - Returned if the password is successfully reset. The response body includes a confirmation message.
/// * `400 Bad Request` - Returned if the reset token is invalid, if the user ID does not match the token's user,
///   or if the new password does not meet the required criteria.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
/// * `500 Internal Server Error` - Returned if an unexpected error occurs during the password reset process.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the password reset process fails at any point,
/// including token verification failures, password validation issues, or internal server errors.
///
/// # ResetPasswordParams Structure
/// - `user_id`: String - The unique identifier of the user.
/// - `token`: String - The password reset verification token.
/// - `password`: String - The new password for the user.
/// - `password_confirm`: String - The confirmation of the new password.
///
#[utoipa::path(
    post,
    path = "/api/auth/password-reset",
    request_body = ResetPasswordParams,
    responses(
         (status = 200, description = "User created successfully"),
         (status = 400, description = "User data invalid"),
         (status = 429, description = "Too Many Requests"),
         (status = 500, description = "Internal Server Error")
    )
)]
pub async fn password_reset(
    req: HttpRequest,
    params: web::Json<ResetPasswordParams>,
) -> Result<HttpResponse, ServiceError> {
    try_reset_password(&req, params.0).await?;
    Ok(HttpResponse::Ok().json("Password successfully reset."))
}
