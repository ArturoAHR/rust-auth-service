use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashSetBannedTokenStore {
    banned_tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn ban_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError> {
        self.banned_tokens.insert(token.to_owned());

        Ok(())
    }

    async fn check_if_token_is_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let banned_token = self.banned_tokens.get(token);

        Ok(banned_token.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn should_ban_token() {
        let mut store = HashSetBannedTokenStore::default();

        let token = "token";

        store.ban_token(token).await.unwrap();

        let stored_token = store.banned_tokens.get(token).unwrap();

        assert_eq!(stored_token, token);
    }

    #[tokio::test]
    async fn should_successfully_check_banned_token() {
        let mut store = HashSetBannedTokenStore::default();

        let token = "token";

        store.ban_token(token).await.unwrap();

        let token_is_banned = store.check_if_token_is_banned(token).await.unwrap();

        assert!(token_is_banned);
    }

    #[tokio::test]
    async fn should_successfully_check_not_banned_token() {
        let store = HashSetBannedTokenStore::default();

        let token = "token";

        let token_is_banned = store.check_if_token_is_banned(token).await.unwrap();

        assert!(!token_is_banned);
    }
}
