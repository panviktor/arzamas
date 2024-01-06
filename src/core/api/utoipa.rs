use utoipa::ToSchema;
pub use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};

use crate::models::ServiceError;
use crate::modules::user::controller::__path_about_me;
use crate::modules::user::models::AboutMeInformation;

#[derive(OpenApi)]
#[openapi(
    paths(
        about_me
    ),
    components(
        schemas(
            ServiceError,
            AboutMeInformation
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
