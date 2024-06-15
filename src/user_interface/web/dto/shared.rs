use actix_http::HttpMessage;
use actix_web::{dev, Error, FromRequest, HttpRequest};
use futures::future::{err, ok, Ready};

#[derive(Debug, Clone)]
pub struct LoginUser {
    pub id: String,
}
impl FromRequest for LoginUser {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
        return match req.extensions().get::<LoginUser>() {
            Some(user) => ok(user.clone()),
            None => err(actix_web::error::ErrorBadRequest("ups...")),
        };
    }
}
