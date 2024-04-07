use crate::domain::entities::shared::{Email, Username};

pub struct FindUserByIdDTO {
    pub user_id: String,
}

pub struct FindUserByEmailDTO {
    pub email: Email,
}

pub struct FindUserByUsernameDTO {
    pub username: Username,
}
