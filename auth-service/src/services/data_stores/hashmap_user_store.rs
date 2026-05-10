use std::collections::HashMap;

use crate::domain::{parse::Email, User, UserStore, UserStoreError};

#[derive(Debug, Default)]
pub struct HashMapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashMapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if let Some(_) = self.users.get(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }

        self.users.insert(user.email.clone(), user);

        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        if let Some(found_user) = self.users.get(email) {
            return Ok(found_user.clone());
        }

        Err(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &Email, password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;

        user.password
            .verify_raw_password(password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::parse::HashedPassword;

    use super::*;

    #[tokio::test]
    async fn should_add_user() -> Result<(), UserStoreError> {
        let mut store = HashMapUserStore::default();

        let user = User::new(
            Email::parse("example@email.com".to_owned()).unwrap(),
            HashedPassword::parse("password123".to_owned())
                .await
                .unwrap(),
            false,
        );

        store.add_user(user.clone()).await?;

        let retrieved_user = store
            .users
            .get(&user.email)
            .ok_or(UserStoreError::UserNotFound)?;

        assert_eq!(*retrieved_user, user);

        Ok(())
    }

    #[tokio::test]
    async fn should_get_user() -> Result<(), UserStoreError> {
        let mut store = HashMapUserStore::default();

        let user = User::new(
            Email::parse("example@email.com".to_owned()).unwrap(),
            HashedPassword::parse("password123".to_owned())
                .await
                .unwrap(),
            false,
        );

        store.add_user(user.clone()).await?;

        let retrieved_user = store.get_user(&user.email).await?;

        assert_eq!(retrieved_user, user);

        Ok(())
    }

    #[tokio::test]
    async fn should_fail_to_get_non_existing_user() {
        let store = HashMapUserStore::default();

        let non_existing_user_email = Email::parse("example@email".to_owned()).unwrap();

        let user_retrieval_result = store.get_user(&non_existing_user_email).await;

        assert_eq!(
            user_retrieval_result.err().unwrap(),
            UserStoreError::UserNotFound
        );
    }

    #[tokio::test]
    async fn should_validate_user() -> Result<(), UserStoreError> {
        let mut store = HashMapUserStore::default();

        let password = "password123".to_owned();

        let user = User::new(
            Email::parse("example@email.com".to_owned()).unwrap(),
            HashedPassword::parse(password.clone()).await.unwrap(),
            false,
        );

        store.add_user(user.clone()).await?;

        store.validate_user(&user.email, &password).await
    }

    #[tokio::test]
    async fn should_not_validate_invalid_credentials() {
        let mut store = HashMapUserStore::default();

        let user = User::new(
            Email::parse("example@email.com".to_owned()).unwrap(),
            HashedPassword::parse("password123".to_owned())
                .await
                .unwrap(),
            false,
        );

        store.add_user(user.clone()).await.unwrap();

        let incorrect_password = "another password".to_owned();

        let validation_result = store.validate_user(&user.email, &incorrect_password).await;

        assert_eq!(
            validation_result.err().unwrap(),
            UserStoreError::InvalidCredentials
        );
    }

    #[tokio::test]
    async fn should_fail_to_validate_non_existing_user() {
        let store = HashMapUserStore::default();

        let non_existing_user_email = Email::parse("example@email".to_owned()).unwrap();
        let non_existing_user_password = "password123".to_owned();

        let validation_result = store
            .validate_user(&non_existing_user_email, &non_existing_user_password)
            .await;

        assert_eq!(
            validation_result.err().unwrap(),
            UserStoreError::UserNotFound
        );
    }
}
