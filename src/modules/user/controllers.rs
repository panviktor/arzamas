use crate::models::many_response::UniversalResponse;
use crate::models::ServiceError;
use crate::modules::auth::middleware::LoginUser;
use crate::modules::auth::session::{
    try_active_sessions, try_current_active_session, try_remove_active_session_token,
    try_remove_all_sessions_token,
};
use crate::modules::user::models::{
    ChangeEmailParams, ChangePasswordParams, MnemonicConfirmation, SecuritySettingsUpdate,
};
use actix_web::{web, HttpRequest, HttpResponse};
use sea_orm::DatabaseConnection;

use crate::modules::user::service::{
    try_2fa_activate, try_2fa_add, try_2fa_remove, try_2fa_reset, try_about_me, try_add_email_2fa,
    try_change_email, try_change_password, try_get_security_settings, try_remove_email_2fa,
    try_resend_verify_email, try_update_security_settings,
};

/// Retrieves information about the currently logged-in user.
///
/// This function is an API endpoint that provides information about the user who is currently logged in.
/// It requires an HTTP request and a `LoginUser` object, which typically includes details such as the user's ID or token.
/// The function then retrieves information specific to the logged-in user.
///
/// This endpoint is protected and requires authentication. The user must provide a valid token to access their information.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request.
/// * `user` - The logged-in user's information, typically including the user's unique identifier.
///
/// # Responses
/// * `200 OK` - Returned if the user information is retrieved successfully. The response body includes the `AboutMeInformation` structure with the user's details.
/// * `401 Unauthorized` - Returned if the user is not authenticated or if the token is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if it fails to retrieve the user information, which could be due to authentication issues, rate-limiting, or other internal server errors.
///
/// # Security
/// The endpoint is secured with a token-based authentication system. The client must include a valid token in the request header to access this endpoint.
///
#[utoipa::path(
    get,
    path = "/api/user/about-me",
    responses(
        (status = 200, description = "User information retrieved successfully", body = AboutMeInformation),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn about_me(
    req: HttpRequest,
    user: LoginUser,
    db: web::Data<DatabaseConnection>,
) -> Result<HttpResponse, ServiceError> {
    let info = try_about_me(&req, &user.id, db).await?;
    Ok(HttpResponse::Ok().json(info))
}

/// Logs out the user from the current session.
///
/// This function is an API endpoint for logging out a user from their current session.
/// It invalidates the session token provided in the request, effectively logging the user out.
///
/// This endpoint requires a valid session token, as it is secured and needs authentication.
///
/// The response is structured using `UniversalResponse` to provide consistent feedback to the client, including a title,
/// an optional description, and a flag indicating whether to show this response to the user.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request, which includes the session token to be invalidated.
///
/// # Responses
/// * `200 OK` - Returned if the logout process is successful. The response body contains a `UniversalResponse` with a success message.
/// * `401 Unauthorized` - Returned if the user is not authenticated or the token is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the logout process fails, which could be due to authentication issues or internal server errors.
///
/// # Security
/// The endpoint is secured with token-based authentication. A valid token is required in the request header for the logout to proceed.
///
#[utoipa::path(
    post,
    path = "/api/user/logout",
    responses(
        (status = 200, description = "Logout from current session", body = UniversalResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn logout(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    try_remove_active_session_token(&req).await?;
    let response = UniversalResponse::new(
        "Logout Successful".to_string(),
        Some("You have been logged out from the current session".to_string()),
        true,
    );
    Ok(HttpResponse::Ok().json(response))
}

/// Logs out the user from all active sessions.
///
/// This function is an API endpoint that handles logging out a user from all their active sessions.
/// It invalidates all session tokens associated with the user, ensuring the user is logged out from all devices or sessions.
/// The function requires a valid authentication token and the logged-in user's information to process the logout.
///
/// The response is structured using `UniversalResponse` to provide consistent feedback to the client, including a title,
/// an optional description, and a flag indicating whether to show this response to the user.
///
/// # Arguments
/// * `user` - The logged-in user's information, typically including the user's unique identifier, used to identify all sessions to be invalidated.
///
/// # Responses
/// * `200 OK` - Returned if the logout process from all sessions is successful. The response body contains a `UniversalResponse` with a success message.
/// * `401 Unauthorized` - Returned if the user is not authenticated or the token is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the logout process from all sessions fails, due to reasons such as authentication issues or internal server errors.
///
/// # Security
/// The endpoint requires token-based authentication. A valid token must be included in the request header for the logout to be effective.
///
#[utoipa::path(
    post,
    path = "/api/user/logout-all",
    responses(
        (status = 200, description = "Logout from all sessions", body = UniversalResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn logout_all(req: HttpRequest, user: LoginUser) -> Result<HttpResponse, ServiceError> {
    try_remove_all_sessions_token(&req, &user.id).await?;
    let response = UniversalResponse::new(
        "Logout Successful".to_string(),
        Some("You have been logged out from all sessions".to_string()),
        true,
    );
    Ok(HttpResponse::Ok().json(response))
}

/// Retrieves the current user's session information.
///
/// This function is an API endpoint that provides information about the current active session for a user.
/// It requires an authenticated request with a valid session token. The function decodes the token,
/// validates its authenticity and expiration, and returns the session details encapsulated in a `UserToken` structure.
///
/// The `UserToken` structure includes details such as the user ID, session ID, issue and expiration timestamps,
/// as well as login IP and user agent of the session.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request, which includes the session token to be validated and decoded.
///
/// # Responses
/// * `200 OK` - Returned if the session information is retrieved successfully. The response body contains the `UserToken` with session details.
/// * `401 Unauthorized` - Returned if the token is invalid or expired.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if it fails to retrieve the session information, which could be due to invalid token, token expiration, or other server-related issues.
///
/// # Security
/// The endpoint requires token-based authentication. A valid token must be included in the request header to access the session information.
///
/// # UserToken Structure
/// - `iat`: i64 - The issued-at timestamp for the token.
/// - `exp`: i64 - The expiration timestamp for the token.
/// - `user_id`: String - The unique identifier of the user.
/// - `session_id`: String - The unique identifier of the session.
/// - `session_name`: String - A random name associated with the session.
/// - `login_ip`: String - The IP address used during login.
/// - `user_agent`: String - The user agent of the browser or client used during login.
///
#[utoipa::path(
    get,
    path = "/api/user/current-session",
    responses(
        (status = 200, description = "User session information retrieved successfully", body = UserToken),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn current_session(req: HttpRequest) -> Result<HttpResponse, ServiceError> {
    let session = try_current_active_session(&req).await?;
    Ok(HttpResponse::Ok().json(session))
}

/// Retrieves all active sessions for the current user.
///
/// This function is an API endpoint that provides a list of all active sessions associated with the currently logged-in user.
/// It requires an authenticated request with a valid session token. The function retrieves the session details for each active session
/// of the user and returns them in an array of `UserToken` structures.
///
/// Each `UserToken` in the response represents a distinct active session, including details such as the user ID, session ID,
/// issue and expiration timestamps, as well as login IP and user agent of the session.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request, which includes the session token.
/// * `user` - The logged-in user's information, including the user's unique identifier.
///
/// # Responses
/// * `200 OK` - Returned if the session information is retrieved successfully. The response body contains an array of `UserToken` structures with details of each session.
/// * `401 Unauthorized` - Returned if the token is invalid or expired.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if it fails to retrieve the session information, which could be due to invalid token, token expiration, or other server-related issues.
///
/// # Security
/// The endpoint requires token-based authentication. A valid token must be included in the request header to access the session information.
///
/// # UserToken Structure
/// - `iat`: i64 - The issued-at timestamp for the token.
/// - `exp`: i64 - The expiration timestamp for the token.
/// - `user_id`: String - The unique identifier of the user.
/// - `session_id`: String - The unique identifier of the session.
/// - `session_name`: String - A random name associated with the session.
/// - `login_ip`: String - The IP address used during login.
/// - `user_agent`: String - The user agent of the browser or client used during login.
///
#[utoipa::path(
    get,
    path = "/api/user/all-sessions",
    responses(
        (status = 200, description = "User sessions information retrieved successfully", body = [UserToken]),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn all_sessions(req: HttpRequest, user: LoginUser) -> Result<HttpResponse, ServiceError> {
    let sessions = try_active_sessions(&req, &user.id).await?;
    Ok(HttpResponse::Ok().json(sessions))
}

/// Changes the password of the currently logged-in user.
///
/// This function is an API endpoint that allows the currently logged-in user to change their password.
/// It requires an authenticated request with a valid session token and the new password details.
/// The function validates the provided current password and new password details against the required criteria
/// and updates the user's password if valid.
///
/// The request must include the `ChangePasswordParams` structure, which contains the current password, the new password,
/// and a confirmation of the new password for verification purposes.
///
/// The response is structured using `UniversalResponse` to provide consistent feedback to the client, including a title,
/// an optional description, and a flag indicating whether to show this response to the user.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request, which includes the session token.
/// * `user` - The logged-in user's information, typically including the user's unique identifier.
/// * `params` - The new password details, wrapped in `web::Json`.
///
/// # Responses
/// * `200 OK` - Returned if the password change is successful. The response body contains a `UniversalResponse` with a success message.
/// * `401 Unauthorized` - Returned if the user is not authenticated or the token is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the password change process fails, which could be due to authentication issues, invalid new password criteria, or internal server errors.
///
/// # Security
/// The endpoint requires token-based authentication. A valid token must be included in the request header to change the password.
///
/// # ChangePasswordParams Structure
/// - `current_password`: String - The current password of the user.
/// - `new_password`: String - The new password that the user wants to set.
/// - `new_password_confirm`: String - Confirmation of the new password for verification purposes.
///
#[utoipa::path(
    post,
    path = "/api/user/change-password",
    request_body = ChangePasswordParams,
    responses(
        (status = 200, description = "Password Changed Successfully", body = UniversalResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn change_password(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<ChangePasswordParams>,
    db: web::Data<DatabaseConnection>,
) -> Result<HttpResponse, ServiceError> {
    try_change_password(&req, &user.id, params.0, db).await?;
    let response = UniversalResponse::new("Password Changed Successfully".to_string(), None, true);
    Ok(HttpResponse::Ok().json(response))
}

/// Changes the email of the currently logged-in user.
///
/// This function is an API endpoint that allows the currently logged-in user to change their email.
/// It requires an authenticated request with a valid session token and the new email details.
/// The function validates the provided current password and new email details against the required criteria
/// and updates the user's email if valid.
///
/// The request must include the `ChangeEmailParams` structure, which contains the current password, the new email,
/// and a confirmation of the new email for verification purposes.
///
/// The response is structured using `UniversalResponse` to provide consistent feedback to the client, including a title,
/// an optional description, and a flag indicating whether to show this response to the user.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request, which includes the session token.
/// * `user` - The logged-in user's information, typically including the user's unique identifier.
/// * `params` - The new email details, wrapped in `web::Json`.
///
/// # Responses
/// * `200 OK` - Returned if the email change is successful. The response body contains a `UniversalResponse` with a success message.
/// * `401 Unauthorized` - Returned if the user is not authenticated or the token is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the email change process fails, which could be due to authentication issues, invalid new email criteria, or internal server errors.
///
/// # Security
/// The endpoint requires token-based authentication. A valid token must be included in the request header to change the email.
///
/// # ChangeEmailParams Structure
/// - `current_password`: String - The current password of the user.
/// - `new_email`: String - The new email that the user wants to set.
/// - `new_email_confirm`: String - Confirmation of the new email for verification purposes.
///
#[utoipa::path(
    post,
    path = "/api/user/change-email",
    request_body = ChangeEmailParams,
    responses(
        (status = 200, description = "Email Changed Successfully", body = UniversalResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn change_email(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<ChangeEmailParams>,
    db: web::Data<DatabaseConnection>,
) -> Result<HttpResponse, ServiceError> {
    try_change_email(&req, &user.id, params.0, db).await?;
    let response = UniversalResponse::new("Email Changed Successfully".to_string(), None, true);
    Ok(HttpResponse::Ok().json(response))
}

/// Resends the email verification link to the user's email.
///
/// This function is an API endpoint that allows a user to request resending of the email verification link.
/// It is useful in cases where the original verification email was not received or has expired.
/// The function requires an authenticated request with a valid session token and is applicable only if the user's email is not already verified.
///
/// The response is structured using `UniversalResponse` to provide a clear and consistent message to the client.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request, which includes the session token.
/// * `user` - The logged-in user's information, including the user's unique identifier.
///
/// # Responses
/// * `200 OK` - Returned if the email verification link is resent successfully. The response body contains a `UniversalResponse` with a success message.
/// * `401 Unauthorized` - Returned if the user is not authenticated or the token is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the email verification link cannot be resent. This could be due to reasons such as the email already being verified, user not found, or internal server errors.
///
/// # Security
/// The endpoint requires token-based authentication. A valid token must be included in the request header for the operation.
///
#[utoipa::path(
    post,
    path = "/api/user/resend-verify-email",
    responses(
        (status = 200, description = "Email Verify Resend Successfully", body = UniversalResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn resend_verify_email(
    req: HttpRequest,
    user: LoginUser,
    db: web::Data<DatabaseConnection>,
) -> Result<HttpResponse, ServiceError> {
    try_resend_verify_email(&req, &user.id, db).await?;
    let response =
        UniversalResponse::new("Email Verify Resend Successfully".to_string(), None, true);
    Ok(HttpResponse::Ok().json(response))
}

/// Retrieves the security settings of the currently logged-in user.
///
/// This function is an API endpoint that provides the security settings associated with the currently logged-in user.
/// It requires an authenticated request with a valid session token. The function fetches and returns the user's security settings,
/// which include two-factor authentication settings, session management, and other security-related preferences.
///
/// The returned `UserSecuritySettings` model contains the detailed security configurations for the user, excluding sensitive fields like the primary key and TOTP secret.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request, which includes the session token.
/// * `user` - The logged-in user's information, typically including the user's unique identifier.
///
/// # Responses
/// * `200 OK` - Returned if the security settings are retrieved successfully. The response body contains the `UserSecuritySettings` model with detailed security configurations.
/// * `401 Unauthorized` - Returned if the user is not authenticated or the token is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if it fails to retrieve the security settings, which could be due to authentication issues, user not found, or internal server errors.
///
/// # Security
/// The endpoint requires token-based authentication. A valid token must be included in the request header to access the security settings.
///
/// # UserSecuritySettings Structure
/// Represents the user's security settings model. This model includes the following fields:
/// - `user_id`: String - The unique identifier of the user.
/// - `two_factor_email`: bool - Indicates if two-factor authentication via email is enabled.
/// - `two_factor_authenticator_app`: bool - Indicates if two-factor authentication via an authenticator app is enabled.
/// - `email_on_success_enabled_at`: bool - Indicates if email notifications on successful login attempts are enabled.
/// - `email_on_failure_enabled_at`: bool - Indicates if email notifications on failed login attempts are enabled.
/// - `close_sessions_on_change_password`: bool - Indicates if all sessions should be closed when the password is changed.
///
/// Note: Sensitive fields like the primary key and TOTP secret are not included in the response for security reasons.
///
#[utoipa::path(
    get,
    path = "/api/user/security-settings",
    responses(
        (status = 200, description = "Security settings retrieved successfully", body = UserSecuritySettings),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn get_security_settings(
    req: HttpRequest,
    user: LoginUser,
    db: web::Data<DatabaseConnection>,
) -> Result<HttpResponse, ServiceError> {
    let info = try_get_security_settings(&req, &user.id, db).await?;
    Ok(HttpResponse::Ok().json(info))
}

//need implement
#[utoipa::path(
    post,
    path = "/api/user/security-settings",
    request_body = SecuritySettingsUpdate,
    responses(
        (status = 200, description = "User information retrieved successfully", body = UpdateSecuritySettingsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn update_security_settings(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<SecuritySettingsUpdate>,
    db: web::Data<DatabaseConnection>,
) -> Result<HttpResponse, ServiceError> {
    try_update_security_settings(&req, &user.id, params.0, db).await?;
    Ok(HttpResponse::Ok().json("get_security_settings"))
}

/// Activates the option to receive two-factor authentication (2FA) codes via email for the user.
///
/// This function is an API endpoint for enabling the feature of sending 2FA codes to the user's registered email address.
/// It requires an authenticated request with a valid session token. Once activated, the user will receive 2FA codes
/// via email for additional security verification during login or other sensitive operations.
///
/// The response indicates the successful activation of this feature and is structured using the standard response format
/// for consistency and clarity.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request, which includes the session token.
/// * `user` - The logged-in user's information, typically including the user's unique identifier.
///
/// # Responses
/// * `200 OK` - Returned if the email 2FA option is activated successfully. The response body contains a confirmation message.
/// * `401 Unauthorized` - Returned if the user is not authenticated or the token is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the process of activating email for 2FA fails, which could be due to authentication issues, user not found, or internal server errors.
///
/// # Security
/// The endpoint requires token-based authentication. A valid token must be included in the request header for the operation.
///
#[utoipa::path(
    post,
    path = "/api/user/2fa-add-email",
    responses(
        (status = 200, description = "Sending an authorization code by email is activated", body = UniversalResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn add_email_2fa(
    req: HttpRequest,
    user: LoginUser,
    db: web::Data<DatabaseConnection>,
) -> Result<HttpResponse, ServiceError> {
    try_add_email_2fa(&req, &user.id, db).await?;
    let response = UniversalResponse::new(
        "Sending an authorization code by email is activated.".to_string(),
        None,
        true,
    );
    Ok(HttpResponse::Ok().json(response))
}

/// Disables the option to receive two-factor authentication (2FA) codes via email for the user.
///
/// This function is an API endpoint for disabling the feature of sending 2FA codes to the user's email address.
/// It requires an authenticated request with a valid session token. Once disabled, the user will no longer receive 2FA codes
/// via email, and will need to use other methods for 2FA verification.
///
/// The response is structured using `UniversalResponse` to provide clear and consistent feedback to the client,
/// including a title, an optional description, and a flag indicating whether to show this response to the user.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request, which includes the session token.
/// * `user` - The logged-in user's information, typically including the user's unique identifier.
///
/// # Responses
/// * `200 OK` - Returned if the email 2FA option is disabled successfully. The response body contains a `UniversalResponse` with a success message.
/// * `401 Unauthorized` - Returned if the user is not authenticated or the token is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the process of disabling email for 2FA fails, which could be due to authentication issues, user not found, or internal server errors.
///
/// # Security
/// The endpoint requires token-based authentication. A valid token must be included in the request header for the operation.
///
#[utoipa::path(
    post,
    path = "/api/user/2fa-remove-email",
    responses(
        (status = 200, description = "Sending an authorization code by email is disabled", body = UniversalResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn remove_email_2fa(
    req: HttpRequest,
    user: LoginUser,
    db: web::Data<DatabaseConnection>,
) -> Result<HttpResponse, ServiceError> {
    try_remove_email_2fa(&req, &user.id, db).await?;
    let response = UniversalResponse::new(
        "Sending an authorization code by email is disabled.".to_string(),
        None,
        true,
    );
    Ok(HttpResponse::Ok().json(response))
}

/// Adds two-factor authentication (2FA) using an authentication app for the user.
///
/// This function is an API endpoint that enables 2FA for the currently logged-in user through an authentication app.
/// It generates a 2FA secret and provides the information necessary to set up the authentication app.
/// The response includes a mnemonic and a base32-encoded secret key, which are required for configuring the authentication app.
///
/// The function requires an authenticated request with a valid session token.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request, which includes the session token.
/// * `user` - The logged-in user's information, typically including the user's unique identifier.
///
/// # Responses
/// * `200 OK` - Returned if the 2FA setup information is generated successfully. The response body contains `AuthenticationAppInformation` with the mnemonic and base32 secret.
/// * `401 Unauthorized` - Returned if the user is not authenticated or the token is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the process of adding 2FA fails, which could be due to authentication issues, user not found, or internal server errors.
///
/// # Security
/// The endpoint requires token-based authentication. A valid token must be included in the request header for the operation.
///
/// # AuthenticationAppInformation Structure
/// - `mnemonic`: String - A mnemonic phrase associated with the user's 2FA setup.
/// - `base32_secret`: String - A base32-encoded secret key for setting up the authentication app.
///
#[utoipa::path(
    post,
    path = "/api/user/2fa-add",
    responses(
    (status = 200, description = "2FA setup information provided successfully", body = AuthenticationAppInformation),
    (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn add_2fa(
    req: HttpRequest,
    user: LoginUser,
    db: web::Data<DatabaseConnection>,
) -> Result<HttpResponse, ServiceError> {
    let json = try_2fa_add(&req, &user.id, db).await?;
    Ok(HttpResponse::Ok().json(json))
}

/// Activates two-factor authentication (2FA) for the user's account.
///
/// This function is an API endpoint that finalizes the activation of 2FA for the currently logged-in user.
/// It requires the user to confirm the mnemonic phrase received during the 2FA setup process.
/// The function verifies the provided mnemonic against the stored one and activates 2FA if the verification is successful.
///
/// The response is structured using `UniversalResponse` to provide clear and informative feedback to the client.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request, which includes the session token.
/// * `user` - The logged-in user's information, typically including the user's unique identifier.
/// * `params` - The mnemonic phrase for confirming 2FA activation, wrapped in `web::Json`.
///
/// # Responses
/// * `200 OK` - Returned if the 2FA activation is successful. The response body contains a `UniversalResponse` with a detailed success message.
/// * `401 Unauthorized` - Returned if the user is not authenticated or the token is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the 2FA activation process fails, which could be due to an incorrect mnemonic phrase, authentication issues, or internal server errors.
///
/// # Security
/// The endpoint requires token-based authentication. A valid token must be included in the request header to activate 2FA.
///
#[utoipa::path(
    post,
    path = "/api/user/2fa-activate",
    request_body = MnemonicConfirmation,
    responses(
        (status = 200, description = "2FA Successfully Activated", body = UniversalResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn activate_2fa(
    req: HttpRequest,
    user: LoginUser,
    params: web::Json<MnemonicConfirmation>,
    db: web::Data<DatabaseConnection>,
) -> Result<HttpResponse, ServiceError> {
    try_2fa_activate(&req, &user.id, params.0, db).await?;
    let response = UniversalResponse::new(
        "2FA Successfully Activated".to_string(),
        Some(
            "Congratulations on successfully setting up two-factor authentication (2FA) for your account!\
             This additional layer of security will help protect your account and ensure that only authorized individuals can access it.\
             Remember to keep your 2FA device or app safe and secure.".to_string()
        ),
        true
    );
    Ok(HttpResponse::Ok().json(response))
}

/// Resets and reconfigures the two-factor authentication (2FA) for the user's account.
///
/// This function is an API endpoint for resetting the user's 2FA configuration. It generates a new 2FA secret
/// and provides the necessary information to set up the authentication app again.
/// The response includes a new mnemonic and a base32-encoded secret key, which are required for reconfiguring the authentication app.
///
/// The function requires an authenticated request with a valid session token.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request, which includes the session token.
/// * `user` - The logged-in user's information, typically including the user's unique identifier.
///
/// # Responses
/// * `200 OK` - Returned if the 2FA reset is successful. The response body contains `AuthenticationAppInformation` with the new mnemonic and base32 secret.
/// * `401 Unauthorized` - Returned if the user is not authenticated or the token is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the 2FA reset process fails, which could be due to authentication issues, user not found, or internal server errors.
///
/// # Security
/// The endpoint requires token-based authentication. A valid token must be included in the request header for the operation.
///
/// # AuthenticationAppInformation Structure
/// - `mnemonic`: String - A new mnemonic phrase associated with the user's 2FA reset.
/// - `base32_secret`: String - A new base32-encoded secret key for setting up the authentication app.
///
#[utoipa::path(
    post,
    path = "/api/user/2fa-reset",
    responses(
        (status = 200, description = "2FA reset information provided successfully", body = AuthenticationAppInformation),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn reset_2fa(
    req: HttpRequest,
    user: LoginUser,
    db: web::Data<DatabaseConnection>,
) -> Result<HttpResponse, ServiceError> {
    let json = try_2fa_reset(&req, &user.id, db).await?;
    Ok(HttpResponse::Ok().json(json))
}

/// Disables two-factor authentication (2FA) for the user's account.
///
/// This function is an API endpoint for disabling 2FA on the user's account.
/// It requires an authenticated request with a valid session token. Once executed, the 2FA feature
/// will be turned off for the user's account, removing the additional layer of security provided by 2FA.
///
/// The response is structured using `UniversalResponse` to provide clear and informative feedback to the client,
/// including a title, an optional description, and a flag indicating whether to show this response to the user.
///
/// # Arguments
/// * `req` - A reference to the incoming HTTP request, which includes the session token.
/// * `user` - The logged-in user's information, typically including the user's unique identifier.
///
/// # Responses
/// * `200 OK` - Returned if 2FA is disabled successfully. The response body contains a `UniversalResponse` with a detailed success message.
/// * `401 Unauthorized` - Returned if the user is not authenticated or the token is invalid.
/// * `429 Too Many Requests` - Returned if the request is rate-limited.
///
/// # Errors
/// This function returns an error (`ServiceError`) if the 2FA removal process fails, which could be due to authentication issues, user not found, or internal server errors.
///
/// # Security
/// The endpoint requires token-based authentication. A valid token must be included in the request header for the operation.
///
#[utoipa::path(
    post,
    path = "/api/user/2fa-remove",
    responses(
        (status = 200, description = "2FA Successfully Removed", body = UniversalResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Too Many Requests"),
    ),
    security(
        ("token" = [])
    )
)]
pub async fn remove_2fa(
    req: HttpRequest,
    user: LoginUser,
    db: web::Data<DatabaseConnection>,
) -> Result<HttpResponse, ServiceError> {
    try_2fa_remove(&req, &user.id, db).await?;
    let response = UniversalResponse::new(
        "2FA Successfully Removed".to_string(),
        Some("Please keep in mind that disabling two-factor authentication (2FA) reduces the security of your account.\
        It is recommended to use alternative security measures such as strong passwords,\
        regular account monitoring,\
        and enabling other security features provided by the platform to maintain the security of your account.".to_string()),
        true,
    );
    Ok(HttpResponse::Ok().json(response))
}
