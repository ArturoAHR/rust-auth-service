use std::sync::Arc;

use auth_service::{
    services::{
        hashmap_user_store::HashMapUserStore, hashset_banned_token_store::HashSetBannedTokenStore,
    },
    utils::constants::prod::APP_ADDRESS,
    AppState, Application,
};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashMapUserStore::default()));
    let banned_token_store = Arc::new(RwLock::new(HashSetBannedTokenStore::default()));
    let app_state = AppState::new(user_store, banned_token_store);

    let app = Application::build(app_state, APP_ADDRESS)
        .await
        .expect("Failed to build the app");

    app.run().await.expect("Failed to run the app");
}
