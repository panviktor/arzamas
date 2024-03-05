use crate::application::dto::paginated_result::PaginatedResult;
use crate::domain::note::note::{Note, NoteText};
use crate::domain::Entity;
use crate::infrastructure::repository::error::{
    RepoCreateError, RepoDeleteError, RepoFindAllError, RepoSelectError, RepoUpdateError,
};
use async_trait::async_trait;
use serde_derive::{Deserialize, Serialize};

pub(crate) mod seaorm_note_repository;
mod seaorm_note_service;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindNote {
    pub user_id: String,
    pub note_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateNote {
    pub user_id: String,
    pub note_id: String,
    pub text: NoteText,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindNotes {
    pub user_id: String,
    pub page: u64,
    pub per_page: u64,
}

impl Entity for Note {}

#[async_trait]
pub trait Repository<T>
where
    T: Entity,
{
    /// Insert the received entity in the persistence system
    async fn create(&self, note: T) -> Result<T, RepoCreateError>;

    /// Find and return one single record from the persistence system
    async fn find_one(&self, note: FindNote) -> Result<T, RepoSelectError>;

    /// Find and return all records corresponding to the search criteria from the persistence system
    async fn find_all(&self, notes: FindNotes) -> Result<PaginatedResult<T>, RepoFindAllError>;

    /// Update one single record already present in the persistence system
    async fn update(&self, note: UpdateNote) -> Result<T, RepoUpdateError>;

    /// Delete one single record from the persistence system
    async fn delete(&self, note: FindNote) -> Result<(), RepoDeleteError>;
}
