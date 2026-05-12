use std::convert::TryInto;
use std::sync::Arc;

use color_eyre::eyre::{Context, Result};
use redis::{ConnectionLike, TypedCommands};
use tokio::sync::RwLock;

use crate::{
    domain::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore<C: ConnectionLike + Send + Sync> {
    connection: Arc<RwLock<C>>,
}

impl<C: ConnectionLike + Send + Sync> RedisBannedTokenStore<C> {
    pub fn new(connection: Arc<RwLock<C>>) -> Self {
        Self { connection }
    }
}

#[async_trait::async_trait]
impl<C: ConnectionLike + Send + Sync> BannedTokenStore for RedisBannedTokenStore<C> {
    async fn ban_token(&mut self, token: &str) -> Result<()> {
        let key = get_key(token);

        let mut connection = self.connection.write().await;

        let expiration_time_seconds: u64 = TOKEN_TTL_SECONDS
            .try_into()
            .wrap_err("Failed to parse token expiration time.")
            .map_err(BannedTokenStoreError::UnexpectedError)?;

        connection
            .set_ex(key, true, expiration_time_seconds)
            .wrap_err("Failed to set banned token in Redis.")
            .map_err(BannedTokenStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool> {
        let key = get_key(token);

        let mut connection = self.connection.write().await;

        let value = connection
            .get(key)
            .wrap_err("Failed to get banned token from Redis.")
            .map_err(BannedTokenStoreError::UnexpectedError)?;

        Ok(value.is_some())
    }
}

const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}

#[cfg(test)]
mod tests {
    use super::*;

    use redis::Value;
    use redis_test::{MockCmd, MockRedisConnection};

    fn get_expiration_time() -> u64 {
        TOKEN_TTL_SECONDS.try_into().unwrap()
    }

    fn create_store(commands: Vec<MockCmd>) -> RedisBannedTokenStore<MockRedisConnection> {
        let connection = Arc::new(RwLock::new(MockRedisConnection::new(commands)));

        RedisBannedTokenStore::new(connection)
    }

    #[tokio::test]
    async fn should_successfully_ban_and_check_banned_token() {
        let token = "token";

        let mock_redis_commands = vec![
            MockCmd::new(
                redis::cmd("SETEX")
                    .arg("banned_token:token")
                    .arg(get_expiration_time())
                    .arg("1"),
                Ok("OK"),
            ),
            MockCmd::new(redis::cmd("GET").arg("banned_token:token"), Ok("1")),
        ];

        let mut store = create_store(mock_redis_commands);

        store.ban_token(token).await.unwrap();

        let token_is_banned = store.contains_token(token).await.unwrap();

        assert!(token_is_banned);
    }

    #[tokio::test]
    async fn should_successfully_check_not_banned_token() {
        let commands = vec![MockCmd::new(
            redis::cmd("GET").arg("banned_token:token"),
            Ok(Value::Nil),
        )];

        let store = create_store(commands);

        let token = "token";

        let token_is_banned = store.contains_token(token).await.unwrap();

        assert!(!token_is_banned);
    }
}
