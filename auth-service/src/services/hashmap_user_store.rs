use std::collections::HashMap;

use crate::domain::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Default)]
struct HashMapUserStore {
    users: HashMap<String, User>,
}

impl HashMapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if let Some(_) = self.users.get(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }

        self.users.insert(user.email.clone(), user);

        Ok(())
    }

    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        if let Some(found_user) = self.users.get(email) {
            return Ok(found_user.clone());
        }

        Err(UserStoreError::UserNotFound)
    }

    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email)?;

        if password != user.password {
            return Err(UserStoreError::InvalidCredentials);
        }

        Ok(())
    }
}

