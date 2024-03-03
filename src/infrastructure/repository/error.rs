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
    Unknown(String),
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