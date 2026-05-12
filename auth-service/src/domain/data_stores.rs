use color_eyre::eyre::{Report, Result};
use thiserror::Error;

use crate::domain::parse::{Email, LoginAttemptId, TwoFactorAuthCode};
use crate::domain::User;

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait::async_trait]
pub trait UserStore: Send + Sync {
    async fn add_user(&mut self, user: User) -> Result<()>;
    async fn get_user(&self, email: &Email) -> Result<User>;
    async fn validate_user(&self, email: &Email, password: &str) -> Result<()>;
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for BannedTokenStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait::async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn ban_token(&mut self, token: &str) -> Result<()>;
    async fn contains_token(&self, token: &str) -> Result<bool>;
}

#[derive(Debug, Error)]
pub enum TwoFactorAuthCodeStoreError {
    #[error("Login attempt not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFactorAuthCodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait::async_trait]
pub trait TwoFactorAuthCodeStore: Send + Sync {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFactorAuthCode,
    ) -> Result<()>;
    async fn remove_code(&mut self, email: &Email) -> Result<()>;
    async fn get_code(&self, email: &Email) -> Result<(LoginAttemptId, TwoFactorAuthCode)>;
}
