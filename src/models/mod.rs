/// Module for data structures used in various parts of the server.

mod server_error;
mod service_error;
pub(crate) mod many_response;

pub use server_error::ErrorCode;
pub use server_error::ServerError;
pub use service_error::ServiceError;