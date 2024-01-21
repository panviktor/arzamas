pub use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};

use crate::modules::auth::models::NewUserParams;

use crate::models::many_response::ManyResponseNotes;
use crate::models::service_error::ServiceErrorSerialized;

use crate::modules::auth;
use crate::modules::auth::models::{
    CreatedUserDTO, ForgotPasswordParams, LoginParams, LoginResponse, OTPCode, ResetPasswordParams,
    VerifyEmailParams,
};

use crate::modules::user;
use crate::modules::user::models::AboutMeInformation;

use crate::modules::notes;
use crate::modules::notes::models::DTONote;
use entity::note::Model as Note;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Arzamas API",
        version = "0.1.0",
        description = "API for Arzamas services",
        license(name = "MIT", url = "https://github.com/panviktor/arzamas/blob/main/LICENSE")
    ),
    paths(
        auth::controllers::create_user,
        auth::controllers::verify_email,
        auth::controllers::login,
        auth::controllers::login_2fa,
        auth::controllers::forgot_password,
        auth::controllers::password_reset,
        user::controllers::about_me,
        notes::controllers::create_note,
        notes::controllers::get_by_id,
        notes::controllers::get_all_notes,
        notes::controllers::delete,
        notes::controllers::update
    ),
    components(
        schemas(
            ServiceErrorSerialized,
            AboutMeInformation,
        ),
        schemas(
            CreatedUserDTO,
            VerifyEmailParams,
            LoginParams,
            OTPCode,
            ForgotPasswordParams,
            ResetPasswordParams,
            LoginResponse
        ),
        schemas(
            NewUserParams
        ),
        schemas(
            DTONote,
            Note,
            ManyResponseNotes,
        )
    ),
    tags(
        (name = "Arzamas API", description = "Arzamas API 1.0")
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap();
        components.add_security_scheme(
            "token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

//CreatedUserDTO
