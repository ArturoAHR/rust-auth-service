use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use color_eyre::eyre::{eyre, Context, Report, Result};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::instrument;

use crate::{
    domain::{parse::Email, BannedTokenStore},
    utils::constants::{JWT_COOKIE_NAME, JWT_SECRET},
};

pub const TOKEN_TTL_SECONDS: i64 = 10 * 60;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Debug, Error)]
pub enum GenerateTokenError {
    #[error("Token error")]
    TokenError(#[source] jsonwebtoken::errors::Error),
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

#[instrument(name = "Generate auth cookie", skip_all)]
pub fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>> {
    let token = generate_auth_token(email)?;

    Ok(create_auth_cookie(token))
}

#[instrument(name = "Create auth cookie", skip_all)]
fn create_auth_cookie(token: SecretString) -> Cookie<'static> {
    let cookie = Cookie::build((JWT_COOKIE_NAME, token.expose_secret().to_owned()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();

    cookie
}

#[instrument(name = "Generate auth token", skip_all)]
fn generate_auth_token(email: &Email) -> Result<SecretString> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS).ok_or(
        GenerateTokenError::UnexpectedError(eyre!("Failed to create expiration time delta.")),
    )?;

    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(GenerateTokenError::UnexpectedError(eyre!(
            "Failed to add expiration time to current time."
        )))?
        .timestamp();

    let exp: usize = exp.try_into().wrap_err(format!(
        "Failed to cast expiration time to usize. Expiration time: {}",
        exp
    ))?;

    let sub = email.as_ref().expose_secret().to_owned();

    let claims = Claims { sub, exp };

    create_token(&claims)
}

#[instrument(name = "Create JWT token from claims", skip_all)]
fn create_token(claims: &Claims) -> Result<SecretString> {
    Ok(SecretString::new(
        encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &EncodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
        )
        .wrap_err("Failed to encode token")?
        .into_boxed_str(),
    ))
}

#[instrument(name = "Validate token", skip_all)]
pub async fn validate_token(
    token: &SecretString,
    banned_token_store: &dyn BannedTokenStore,
) -> Result<Claims> {
    let is_token_banned = banned_token_store
        .contains_token(token)
        .await
        .wrap_err("Failed to verify if the token is banned.")?;

    if is_token_banned {
        return Err(eyre!("Token is banned."));
    }

    decode::<Claims>(
        token.expose_secret(),
        &DecodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .wrap_err("Failed to decode token.")
}

#[cfg(test)]
mod tests {
    use crate::services::hashset_banned_token_store::HashSetBannedTokenStore;

    use super::*;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = SecretString::new("test_token".to_owned().into_boxed_str());
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token.expose_secret());
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let result = generate_auth_token(&email)
            .unwrap()
            .expose_secret()
            .to_owned();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let token = generate_auth_token(&email).unwrap();

        let store = HashSetBannedTokenStore::default();

        let result = validate_token(&token, &store).await.unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let token = SecretString::new("invalid_token".to_owned().into_boxed_str());
        let store = HashSetBannedTokenStore::default();

        let result = validate_token(&token, &store).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_banned_token() {
        let email = Email::parse(SecretString::new(
            "test@example.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let token = generate_auth_token(&email).unwrap();

        let mut store = HashSetBannedTokenStore::default();

        store.ban_token(&token).await.unwrap();

        let result = validate_token(&token, &store).await;
        assert!(result.is_err());
    }
}
