use crate::domain::note::note::Note;
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
pub struct FindNotes {
    pub user_id: String,
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
    async fn find_all(&self, notes: FindNotes) -> Result<Vec<T>, RepoFindAllError>;

    /// Update one single record already present in the persistence system
    async fn update(&self, note: T) -> Result<T, RepoUpdateError>;

    /// Delete one single record from the persistence system
    async fn delete(&self, note_id: &str, user_id: &str) -> Result<(), RepoDeleteError>;
}
