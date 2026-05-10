use std::ops::Deref;

use argon2::password_hash;
use sqlx::{postgres::PgRow, PgPool};

use crate::domain::{
    parse::{Email, HashedPassword},
    User, UserStore, UserStoreError,
};

#[derive(sqlx::FromRow)]
struct DatabaseUser {
    email: String,
    password_hash: String,
    requires_2fa: bool,
}

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        PostgresUserStore { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        match &self.get_user(&user.email).await {
            Ok(_) => Err(UserStoreError::UserAlreadyExists),
            Err(UserStoreError::UserNotFound) => Ok(()),
            Err(err) => Err(err.to_owned()),
        }?;

        sqlx::query("INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)")
            .bind(user.email.as_ref())
            .bind(user.password.as_ref())
            .bind(user.requires_2fa)
            .execute(&self.pool)
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let user = sqlx::query_as::<_, DatabaseUser>("SELECT * FROM users WHERE email = $1")
            .bind(email.as_ref())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                println!("{}", e.to_string());
                UserStoreError::UnexpectedError
            })?
            .ok_or_else(|| UserStoreError::UserNotFound)?;

        let email = Email::parse(user.email).map_err(|_| UserStoreError::UnexpectedError)?;
        let password_hash = HashedPassword::parse_password_hash(user.password_hash)
            .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(User::new(email, password_hash, user.requires_2fa))
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

    #[sqlx::test]
    async fn should_add_and_get_user(pool: PgPool) -> Result<(), UserStoreError> {
        println!("{:?}", pool);
        let mut store = PostgresUserStore::new(pool);

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

        drop(store);
        Ok(())
    }

    #[sqlx::test]
    async fn should_fail_to_get_non_existing_user(pool: PgPool) {
        let store = PostgresUserStore::new(pool);

        let non_existing_user_email = Email::parse("example@email".to_owned()).unwrap();

        let user_retrieval_result = store.get_user(&non_existing_user_email).await;

        assert_eq!(
            user_retrieval_result.err().unwrap(),
            UserStoreError::UserNotFound
        );

        drop(store);
    }

    #[sqlx::test]
    async fn should_validate_user(pool: PgPool) -> Result<(), UserStoreError> {
        let mut store = PostgresUserStore::new(pool);

        let password = "password123".to_owned();

        let user = User::new(
            Email::parse("example@email.com".to_owned()).unwrap(),
            HashedPassword::parse(password.clone()).await.unwrap(),
            false,
        );

        store.add_user(user.clone()).await?;

        let result = store.validate_user(&user.email, &password).await;

        drop(store);
        result
    }

    #[sqlx::test]
    async fn should_not_validate_invalid_credentials(pool: PgPool) {
        let mut store = PostgresUserStore::new(pool);

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

        drop(store);
    }

    #[sqlx::test]
    async fn should_fail_to_validate_non_existing_user(pool: PgPool) {
        let store = PostgresUserStore::new(pool);

        let non_existing_user_email = Email::parse("example@email".to_owned()).unwrap();
        let non_existing_user_password = "password123".to_owned();

        let validation_result = store
            .validate_user(&non_existing_user_email, &non_existing_user_password)
            .await;

        assert_eq!(
            validation_result.err().unwrap(),
            UserStoreError::UserNotFound
        );

        drop(store);
    }
}
