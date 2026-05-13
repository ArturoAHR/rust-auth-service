use std::sync::Arc;

use auth_service::{
    domain::{BannedTokenStore, TwoFactorAuthCodeStore},
    get_postgres_pool, get_redis_client,
    services::{
        mock_email_client::MockEmailClient, postgres_user_store::PostgresUserStore,
        redis_banned_token_store::RedisBannedTokenStore,
        redis_two_factor_auth_code_store::RedisTwoFactorAuthStore,
    },
    utils::constants::{test::APP_ADDRESS, DATABASE_URL, REDIS_HOST_NAME},
    AppState, Application,
};
use reqwest::{cookie::Jar, Client, Response};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use sqlx::{postgres::PgPoolOptions, Connection, PgConnection, PgPool};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub client: Client,
    pub banned_token_store: Arc<RwLock<dyn BannedTokenStore>>,
    pub two_factor_auth_code_store: Arc<RwLock<dyn TwoFactorAuthCodeStore>>,
    database_name: String,
    cleaned_up: bool,
}

impl TestApp {
    pub async fn new() -> Self {
        let pg_pool = configure_postgresql().await;
        let redis_connection = Arc::new(RwLock::new(configure_redis()));

        let database_name = pg_pool.connect_options().get_database().unwrap().to_owned();

        let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
        let banned_token_store: Arc<RwLock<dyn BannedTokenStore>> = Arc::new(RwLock::new(
            RedisBannedTokenStore::new(Arc::clone(&redis_connection)),
        ));
        let two_factor_auth_code_store: Arc<RwLock<dyn TwoFactorAuthCodeStore>> = Arc::new(
            RwLock::new(RedisTwoFactorAuthStore::new(Arc::clone(&redis_connection))),
        );
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
            database_name,
            cleaned_up: false,
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

    pub async fn clean_up(&mut self) {
        delete_database(&self.database_name).await;
        self.cleaned_up = true;
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if !self.cleaned_up {
            panic!("Error: Test Application hasn't been cleaned up, call the cleanup function at the end of the test.")
        }
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

async fn configure_postgresql() -> PgPool {
    let database_url = DATABASE_URL.expose_secret().to_owned();

    let database_name = Uuid::new_v4().to_string();

    configure_database(&database_url, &database_name).await;

    let database_url_with_name = format!("{}/{}", database_url, database_name);

    get_postgres_pool(&SecretString::new(database_url_with_name.into_boxed_str()))
        .await
        .expect("Failed to create Postgres connection pool.")
}

async fn configure_database(database_url: &str, database_name: &str) {
    let pool = PgPoolOptions::new()
        .connect(database_url)
        .await
        .expect("Failed to create Postgres connection pool.");

    sqlx::query(format!(r#"CREATE DATABASE "{}";"#, database_name).as_str())
        .execute(&pool)
        .await
        .expect("Failed to create database.");

    let database_url_with_name = format!("{}/{}", database_url, database_name);

    let pool = PgPoolOptions::new()
        .connect(&database_url_with_name)
        .await
        .expect("Failed to create Postgres connection pool.");

    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("Failed to migrate the database.");
}

async fn delete_database(database_name: &str) {
    let database_url = DATABASE_URL.expose_secret().to_owned();

    let mut connection = PgConnection::connect(&database_url)
        .await
        .expect("Failed to connect to Postgres.");

    sqlx::query(&format!(
        r#"
            SELECT pg_terminate_backend(pg_stat_activity.pid)
            FROM pg_stat_activity
            WHERE pg_stat_activity.datname = '{}'
                AND pid <> pg_backend_pid();
        "#,
        database_name
    ))
    .execute(&mut connection)
    .await
    .expect("Failed to drop database connections.");

    sqlx::query(&format!(r#"DROP DATABASE "{}";"#, database_name).as_str())
        .execute(&mut connection)
        .await
        .expect("Failed to drop the database.");
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}
