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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_add_user() -> Result<(), UserStoreError> {
        let mut store = HashMapUserStore::default();

        let user = User {
            email: "example@email.com".to_owned(),
            password: "password123".to_owned(),
            requires_2fa: false,
        };

        store.add_user(user.clone())?;

        let retrieved_user = store
            .users
            .get(&user.email)
            .ok_or(UserStoreError::UserNotFound)?;

        assert_eq!(*retrieved_user, user);

        Ok(())
    }

    #[test]
    fn should_get_user() -> Result<(), UserStoreError> {
        let mut store = HashMapUserStore::default();

        let user = User {
            email: "example@email.com".to_owned(),
            password: "password123".to_owned(),
            requires_2fa: false,
        };

        store.add_user(user.clone())?;

        let retrieved_user = store.get_user(&user.email)?;

        assert_eq!(retrieved_user, user);

        Ok(())
    }

    #[test]
    fn should_fail_to_get_non_existing_user() {
        let store = HashMapUserStore::default();

        let user_retrieval_result = store.get_user("example@email.com");

        assert_eq!(
            user_retrieval_result.err().unwrap(),
            UserStoreError::UserNotFound
        );
    }

    #[test]
    fn should_validate_user() -> Result<(), UserStoreError> {
        let mut store = HashMapUserStore::default();

        let user = User {
            email: "example@email.com".to_owned(),
            password: "password123".to_owned(),
            requires_2fa: false,
        };

        store.add_user(user.clone())?;

        store.validate_user(&user.email, &user.password)
    }

    #[test]
    fn should_not_validate_invalid_credentials() {
        let mut store = HashMapUserStore::default();

        let user = User {
            email: "example@email.com".to_owned(),
            password: "password123".to_owned(),
            requires_2fa: false,
        };

        store.add_user(user.clone()).unwrap();

        let validation_result = store.validate_user(&user.email, "another password");

        assert_eq!(
            validation_result.err().unwrap(),
            UserStoreError::InvalidCredentials
        );
    }

    #[test]
    fn should_fail_to_validate_non_existing_user() {
        let store = HashMapUserStore::default();

        let validation_result = store.validate_user("example@email", "password123");

        assert_eq!(
            validation_result.err().unwrap(),
            UserStoreError::UserNotFound
        );
    }
}
