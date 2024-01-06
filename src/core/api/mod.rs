mod utoipa;
use crate::core::api::utoipa::ApiDoc;
use utoipa::OpenApi;

use actix_web::web;
use utoipa_rapidoc::RapiDoc;
use utoipa_swagger_ui::SwaggerUi;

pub fn configure_documentation_services() -> actix_web::Scope {
    let openapi = ApiDoc::openapi();

    web::scope("/api-docs")
        .service(RapiDoc::new("/api-docs/openapi.json").path("/rapidoc"))
        .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", openapi.clone()))
}
