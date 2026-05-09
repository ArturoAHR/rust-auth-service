use std::sync::Arc;

use auth_service::{
    domain::{BannedTokenStore, TwoFactorAuthCodeStore},
    services::{
        hashmap_two_factor_auth_code_store::HashMapTwoFactorAuthCodeStore,
        hashmap_user_store::HashMapUserStore, hashset_banned_token_store::HashSetBannedTokenStore,
        mock_email_client::MockEmailClient,
    },
    utils::constants::test::APP_ADDRESS,
    AppState, Application,
};
use reqwest::{cookie::Jar, Client, Response};
use serde::Serialize;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub client: Client,
    pub banned_token_store: Arc<RwLock<dyn BannedTokenStore>>,
    pub two_factor_auth_code_store: Arc<RwLock<dyn TwoFactorAuthCodeStore>>,
}

impl TestApp {
    pub async fn new() -> Self {
        let user_store = Arc::new(RwLock::new(HashMapUserStore::default()));
        let banned_token_store: Arc<RwLock<dyn BannedTokenStore>> =
            Arc::new(RwLock::new(HashSetBannedTokenStore::default()));
        let two_factor_auth_code_store: Arc<RwLock<dyn TwoFactorAuthCodeStore>> =
            Arc::new(RwLock::new(HashMapTwoFactorAuthCodeStore::default()));
        let email_client = Arc::new(RwLock::new(MockEmailClient {}));

        let app_state = AppState::new(
            user_store,
            Arc::clone(&banned_token_store),
            Arc::clone(&two_factor_auth_code_store),
            email_client,
        );

        let app = Application::build(app_state, APP_ADDRESS)
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        let _ = tokio::spawn(app.run());

        let cookie_jar = Arc::new(Jar::default());
        let client = Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        TestApp {
            address,
            cookie_jar,
            client,
            banned_token_store,
            two_factor_auth_code_store,
        }
    }

    pub async fn get_root(&self) -> Response {
        self.client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_sign_up<Body>(&self, body: &Body) -> Response
    where
        Body: Serialize,
    {
        self.client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> Response
    where
        Body: Serialize,
    {
        self.client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> Response
    where
        Body: Serialize,
    {
        self.client
            .post(&format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_logout(&self) -> Response {
        self.client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> Response
    where
        Body: Serialize,
    {
        self.client
            .post(&format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
