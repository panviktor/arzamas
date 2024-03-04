use actix_web::http::StatusCode;
use crate::application::error::response_error::AppResponseError;

#[derive(Debug)]
pub enum RepositoryError {
    CreateError(RepoCreateError),
    SelectError(RepoSelectError),
    FindAllError(RepoFindAllError),
    UpdateError(RepoUpdateError),
    DeleteError(RepoDeleteError),
}

#[derive(Debug)]
pub enum RepoCreateError {
    InvalidData(String),
    Unknown(String),
}

#[derive(Debug)]
pub enum RepoSelectError {
    NotFound(String),
    Unknown(String),
}

#[derive(Debug)]
pub enum RepoFindAllError {
    DatabaseError(String),
    Unknown(String),
}

impl From<sea_orm::DbErr> for RepoFindAllError {
    fn from(err: sea_orm::DbErr) -> Self {
        // You can define the conversion logic here.
        // For example, you might have a variant of RepoFindAllError specifically for database errors.
        RepoFindAllError::DatabaseError(err.to_string())
    }
}

#[derive(Debug)]
pub enum RepoUpdateError {
    InvalidData(String),
    NotFound(String),
    Unknown(String),
}

#[derive(Debug)]
pub enum RepoDeleteError {
    NotFound(String),
    InvalidData(String),
    Unknown(String),
}

impl From<RepoSelectError> for RepositoryError {
    fn from(error: RepoSelectError) -> Self {
        RepositoryError::SelectError(error)
    }
}

impl From<RepoFindAllError> for RepositoryError {
    fn from(error: RepoFindAllError) -> Self {
        RepositoryError::FindAllError(error)
    }
}

impl From<RepoUpdateError> for RepositoryError {
    fn from(error: RepoUpdateError) -> Self {
        RepositoryError::UpdateError(error)
    }
}

impl From<RepoDeleteError> for RepositoryError {
    fn from(error: RepoDeleteError) -> Self {
        RepositoryError::DeleteError(error)
    }
}

impl From<RepoCreateError> for RepositoryError {
    fn from(error: RepoCreateError) -> Self {
        RepositoryError::CreateError(error)
    }
}

impl std::fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepositoryError::CreateError(err) => write!(f, "Create error: {:?}", err),
            RepositoryError::SelectError(err) => write!(f, "Select error: {:?}", err),
            RepositoryError::FindAllError(err) => write!(f, "Find all error: {:?}", err),
            RepositoryError::UpdateError(err) => write!(f, "Update error: {:?}", err),
            RepositoryError::DeleteError(err) => write!(f, "Delete error: {:?}", err),
        }
    }
}

pub trait IntoServiceError {
    fn into_service_error(self, path: &str) -> AppResponseError;
}

impl IntoServiceError for RepositoryError {
    fn into_service_error(self, path: &str) -> AppResponseError {
        match self {
            RepositoryError::CreateError(err) => match err {
                RepoCreateError::InvalidData(detail) => AppResponseError {
                    code: StatusCode::BAD_REQUEST,
                    path: Some(path.to_owned()),
                    message: format!("Invalid data: {}", detail),
                    show_message: true,
                },
                RepoCreateError::Unknown(detail) => AppResponseError {
                    code: StatusCode::INTERNAL_SERVER_ERROR,
                    path: Some(path.to_owned()),
                    message: format!("Unknown error: {}", detail),
                    show_message: true,
                },
            },
            RepositoryError::SelectError(err) => match err {
                RepoSelectError::NotFound(detail) => AppResponseError {
                    code: StatusCode::NOT_FOUND,
                    path: Some(path.to_owned()),
                    message: format!("Not found: {}", detail),
                    show_message: true,
                },
                RepoSelectError::Unknown(detail) => AppResponseError {
                    code: StatusCode::INTERNAL_SERVER_ERROR,
                    path: Some(path.to_owned()),
                    message: format!("Unknown error: {}", detail),
                    show_message: true,
                },
            },
            // Continue for other error types...
            RepositoryError::FindAllError(err) => AppResponseError {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                path: Some(path.to_owned()),
                message: format!("Find all error: {:?}", err),
                show_message: true,
            },
            RepositoryError::UpdateError(err) => AppResponseError {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                path: Some(path.to_owned()),
                message: format!("Update error: {:?}", err),
                show_message: true,
            },
            RepositoryError::DeleteError(err) => AppResponseError {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                path: Some(path.to_owned()),
                message: format!("Delete error: {:?}", err),
                show_message: true,
            },
        }
    }
}