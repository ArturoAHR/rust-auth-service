use std::sync::Arc;

use redis::{Connection, TypedCommands};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{
    parse::{Email, LoginAttemptId, TwoFactorAuthCode},
    TwoFactorAuthCodeStore, TwoFactorAuthCodeStoreError,
};

pub struct RedisTwoFactorAuthStore {
    connection: Arc<RwLock<Connection>>,
}

impl RedisTwoFactorAuthStore {
    pub fn new(connection: Arc<RwLock<Connection>>) -> Self {
        Self { connection }
    }
}

#[async_trait::async_trait]
impl TwoFactorAuthCodeStore for RedisTwoFactorAuthStore {
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
