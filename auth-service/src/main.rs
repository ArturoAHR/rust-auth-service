use std::sync::Arc;

use auth_service::{
    services::{
        hashmap_two_factor_auth_code_store::HashMapTwoFactorAuthCodeStore,
        hashmap_user_store::HashMapUserStore, hashset_banned_token_store::HashSetBannedTokenStore,
        mock_email_client::MockEmailClient,
    },
    utils::constants::prod::APP_ADDRESS,
    AppState, Application,
};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashMapUserStore::default()));
    let banned_token_store = Arc::new(RwLock::new(HashSetBannedTokenStore::default()));
    let two_factor_auth_code_store =
        Arc::new(RwLock::new(HashMapTwoFactorAuthCodeStore::default()));
    let email_client = Arc::new(RwLock::new(MockEmailClient {}));

    let app_state = AppState::new(
        user_store,
        banned_token_store,
        two_factor_auth_code_store,
        email_client,
    );

    let app = Application::build(app_state, APP_ADDRESS)
        .await
        .expect("Failed to build the app");

    app.run().await.expect("Failed to run the app");
}
