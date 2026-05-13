use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use tracing::instrument;

use crate::domain::{
    parse::{Email, HashedPassword},
    User, UserStore, UserStoreError,
};

#[derive(sqlx::FromRow)]
struct DatabaseUser {
    email: SecretString,
    password_hash: SecretString,
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
    #[instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<()> {
        sqlx::query!(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
            user.email.as_ref().expose_secret(),
            user.password.as_ref().expose_secret(),
            user.requires_2fa
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

        Ok(())
    }

    #[instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> Result<User> {
        let user = sqlx::query_as!(
            DatabaseUser,
            "SELECT * FROM users WHERE email = $1",
            email.as_ref().expose_secret()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?
        .ok_or_else(|| UserStoreError::UserNotFound)?;

        let email =
            Email::parse(user.email).map_err(|e| UserStoreError::UnexpectedError(e.into()))?;
        let password_hash = HashedPassword::parse_password_hash(user.password_hash)
            .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?;

        Ok(User::new(email, password_hash, user.requires_2fa))
    }

    #[instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
    async fn validate_user(&self, email: &Email, password: &SecretString) -> Result<()> {
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
    async fn should_add_and_get_user(pool: PgPool) -> Result<()> {
        println!("{:?}", pool);
        let mut store = PostgresUserStore::new(pool);

        let user = User::new(
            Email::parse(SecretString::new(
                "example@email.com".to_owned().into_boxed_str(),
            ))
            .unwrap(),
            HashedPassword::parse(SecretString::new("password123".to_owned().into_boxed_str()))
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

        let non_existing_user_email = Email::parse(SecretString::new(
            "example@email.com".to_owned().into_boxed_str(),
        ))
        .unwrap();

        let user_retrieval_result = store.get_user(&non_existing_user_email).await;

        assert_eq!(
            user_retrieval_result
                .err()
                .unwrap()
                .downcast::<UserStoreError>()
                .unwrap(),
            UserStoreError::UserNotFound
        );

        drop(store);
    }

    #[sqlx::test]
    async fn should_validate_user(pool: PgPool) -> Result<()> {
        let mut store = PostgresUserStore::new(pool);

        let password = SecretString::new("password123".to_owned().into_boxed_str());

        let user = User::new(
            Email::parse(SecretString::new(
                "example@email.com".to_owned().into_boxed_str(),
            ))
            .unwrap(),
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
            Email::parse(SecretString::new(
                "example@email.com".to_owned().into_boxed_str(),
            ))
            .unwrap(),
            HashedPassword::parse(SecretString::new("password123".to_owned().into_boxed_str()))
                .await
                .unwrap(),
            false,
        );

        store.add_user(user.clone()).await.unwrap();

        let incorrect_password = SecretString::new("another password".to_owned().into_boxed_str());

        let validation_result = store.validate_user(&user.email, &incorrect_password).await;

        assert_eq!(
            validation_result
                .err()
                .unwrap()
                .downcast::<UserStoreError>()
                .unwrap(),
            UserStoreError::InvalidCredentials
        );

        drop(store);
    }

    #[sqlx::test]
    async fn should_fail_to_validate_non_existing_user(pool: PgPool) {
        let store = PostgresUserStore::new(pool);

        let non_existing_user_email = Email::parse(SecretString::new(
            "example@email.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let non_existing_user_password =
            SecretString::new("password123".to_owned().into_boxed_str());

        let validation_result = store
            .validate_user(&non_existing_user_email, &non_existing_user_password)
            .await;

        assert_eq!(
            validation_result
                .err()
                .unwrap()
                .downcast::<UserStoreError>()
                .unwrap(),
            UserStoreError::UserNotFound
        );

        drop(store);
    }
}
