use std::collections::HashMap;

use color_eyre::eyre::Result;

use crate::domain::{
    parse::{Email, LoginAttemptId, TwoFactorAuthCode},
    TwoFactorAuthCodeStore, TwoFactorAuthCodeStoreError,
};

#[derive(Default)]
pub struct HashMapTwoFactorAuthCodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFactorAuthCode)>,
}

#[async_trait::async_trait]
impl TwoFactorAuthCodeStore for HashMapTwoFactorAuthCodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFactorAuthCode,
    ) -> Result<()> {
        self.codes.insert(email, (login_attempt_id, code));

        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<()> {
        self.codes.remove(email);

        Ok(())
    }

    async fn get_code(&self, email: &Email) -> Result<(LoginAttemptId, TwoFactorAuthCode)> {
        let login_attempt_code = self
            .codes
            .get(email)
            .ok_or(TwoFactorAuthCodeStoreError::LoginAttemptIdNotFound)?;

        Ok(login_attempt_code.clone())
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    #[tokio::test]
    async fn should_add_two_factor_auth_code() {
        let mut store = HashMapTwoFactorAuthCodeStore::default();

        let email = Email::parse(SecretString::new(
            "example@email.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFactorAuthCode::default();

        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();

        let added_code = store.codes.get(&email).unwrap();

        assert_eq!(*added_code, (login_attempt_id, code));
    }

    #[tokio::test]
    async fn should_get_two_factor_auth_code() {
        let mut store = HashMapTwoFactorAuthCodeStore::default();

        let email = Email::parse(SecretString::new(
            "example@email.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFactorAuthCode::default();

        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();

        let added_code = store.get_code(&email).await.unwrap();

        assert_eq!(added_code, (login_attempt_id, code));
    }

    #[tokio::test]
    async fn should_fail_to_get_nonexistent_code() {
        let store = HashMapTwoFactorAuthCodeStore::default();

        let email = Email::parse(SecretString::new(
            "example@email.com".to_owned().into_boxed_str(),
        ))
        .unwrap();

        let get_code_error = store
            .get_code(&email)
            .await
            .err()
            .unwrap()
            .downcast::<TwoFactorAuthCodeStoreError>()
            .unwrap();

        assert_eq!(
            get_code_error,
            TwoFactorAuthCodeStoreError::LoginAttemptIdNotFound
        );
    }

    #[tokio::test]
    async fn should_remove_two_factor_auth_code() {
        let mut store = HashMapTwoFactorAuthCodeStore::default();

        let email = Email::parse(SecretString::new(
            "example@email.com".to_owned().into_boxed_str(),
        ))
        .unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFactorAuthCode::default();

        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();

        store.remove_code(&email).await.unwrap();

        let removed_code = store.codes.get(&email);

        assert!(removed_code.is_none());
    }
}
