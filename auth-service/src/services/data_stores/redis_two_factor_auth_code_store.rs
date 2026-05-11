use std::sync::Arc;

use redis::{ConnectionLike, TypedCommands};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{
    parse::{Email, LoginAttemptId, TwoFactorAuthCode},
    TwoFactorAuthCodeStore, TwoFactorAuthCodeStoreError,
};

pub struct RedisTwoFactorAuthStore<C: ConnectionLike + Send + Sync> {
    connection: Arc<RwLock<C>>,
}

impl<C: ConnectionLike + Send + Sync> RedisTwoFactorAuthStore<C> {
    pub fn new(connection: Arc<RwLock<C>>) -> Self {
        Self { connection }
    }
}

#[async_trait::async_trait]
impl<C: ConnectionLike + Send + Sync> TwoFactorAuthCodeStore for RedisTwoFactorAuthStore<C> {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFactorAuthCode,
    ) -> Result<(), TwoFactorAuthCodeStoreError> {
        let key = get_key(&email);

        let record = TwoFactorAuthCodeRecord(
            login_attempt_id.as_ref().to_owned(),
            code.as_ref().to_owned(),
        );

        let serialized_record = serde_json::to_string(&record)
            .map_err(|_| TwoFactorAuthCodeStoreError::UnexpectedError)?;

        let mut connection = self.connection.write().await;

        connection
            .set_ex(key, serialized_record, RECORD_EXPIRATION_TIME_SECONDS)
            .map_err(|_| TwoFactorAuthCodeStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFactorAuthCodeStoreError> {
        let key = get_key(&email);

        let mut connection = self.connection.write().await;

        connection
            .del(key)
            .map_err(|_| TwoFactorAuthCodeStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFactorAuthCode), TwoFactorAuthCodeStoreError> {
        let key = get_key(&email);

        let mut connection = self.connection.write().await;

        let raw_record = connection
            .get(key)
            .map_err(|_| TwoFactorAuthCodeStoreError::UnexpectedError)?
            .ok_or(TwoFactorAuthCodeStoreError::LoginAttemptIdNotFound)?;

        let record: TwoFactorAuthCodeRecord = serde_json::from_str(&raw_record)
            .map_err(|_| TwoFactorAuthCodeStoreError::UnexpectedError)?;

        let login_attempt_id = LoginAttemptId::parse(record.0)
            .map_err(|_| TwoFactorAuthCodeStoreError::UnexpectedError)?;
        let two_factor_auth_code = TwoFactorAuthCode::parse(record.1)
            .map_err(|_| TwoFactorAuthCodeStoreError::UnexpectedError)?;

        Ok((login_attempt_id, two_factor_auth_code))
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFactorAuthCodeRecord(pub String, pub String);

const RECORD_EXPIRATION_TIME_SECONDS: u64 = 600;
const TWO_FACTOR_AUTH_CODE_PREFIX: &str = "two_factor_auth_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FACTOR_AUTH_CODE_PREFIX, email.as_ref())
}

#[cfg(test)]
mod tests {
    use redis::Value;
    use redis_test::{MockCmd, MockRedisConnection};

    use super::*;

    fn create_store(commands: Vec<MockCmd>) -> RedisTwoFactorAuthStore<MockRedisConnection> {
        let connection = Arc::new(RwLock::new(MockRedisConnection::new(commands)));

        RedisTwoFactorAuthStore::new(connection)
    }

    #[tokio::test]
    async fn should_add_and_get_two_factor_auth_code() {
        let email = Email::parse("example@email.com".to_owned()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFactorAuthCode::default();

        let serialized_record = serde_json::to_string(&TwoFactorAuthCodeRecord(
            login_attempt_id.as_ref().to_owned(),
            code.as_ref().to_owned(),
        ))
        .unwrap();

        let commands = vec![
            MockCmd::new(
                redis::cmd("SETEX")
                    .arg("two_factor_auth_code:example@email.com")
                    .arg(RECORD_EXPIRATION_TIME_SECONDS)
                    .arg(serialized_record.clone()),
                Ok("OK"),
            ),
            MockCmd::new(
                redis::cmd("GET").arg("two_factor_auth_code:example@email.com"),
                Ok(serialized_record),
            ),
        ];

        let mut store = create_store(commands);

        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();

        let added_code = store.get_code(&email).await.unwrap();

        assert_eq!(added_code, (login_attempt_id, code));
    }

    #[tokio::test]
    async fn should_fail_to_get_nonexistent_code() {
        let commands = vec![MockCmd::new(
            redis::cmd("GET").arg("two_factor_auth_code:example@email.com"),
            Ok(Value::Nil),
        )];

        let store = create_store(commands);

        let email = Email::parse("example@email.com".to_owned()).unwrap();

        let get_code_error = store.get_code(&email).await.err().unwrap();

        assert_eq!(
            get_code_error,
            TwoFactorAuthCodeStoreError::LoginAttemptIdNotFound
        );
    }

    #[tokio::test]
    async fn should_remove_two_factor_auth_code() {
        let email = Email::parse("example@email.com".to_owned()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFactorAuthCode::default();

        let serialized_record = serde_json::to_string(&TwoFactorAuthCodeRecord(
            login_attempt_id.as_ref().to_owned(),
            code.as_ref().to_owned(),
        ))
        .unwrap();

        let commands = vec![
            MockCmd::new(
                redis::cmd("SETEX")
                    .arg("two_factor_auth_code:example@email.com")
                    .arg(RECORD_EXPIRATION_TIME_SECONDS)
                    .arg(serialized_record.clone()),
                Ok("OK"),
            ),
            MockCmd::new(
                redis::cmd("DEL").arg("two_factor_auth_code:example@email.com"),
                Ok("1"),
            ),
            MockCmd::new(
                redis::cmd("GET").arg("two_factor_auth_code:example@email.com"),
                Ok(Value::Nil),
            ),
        ];

        let mut store = create_store(commands);

        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();

        store.remove_code(&email).await.unwrap();

        let get_code_error = store.get_code(&email).await.err().unwrap();

        assert_eq!(
            get_code_error,
            TwoFactorAuthCodeStoreError::LoginAttemptIdNotFound
        );
    }
}
