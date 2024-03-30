#[derive(Debug, Clone)]
pub enum ApplicationError {
    ValidationError(String),
    NotFound(String),
    BadRequest(String),
    DatabaseError(String),
    InternalServerError(String),
    Unknown(String),
}
