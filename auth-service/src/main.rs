use std::sync::Arc;

use auth_service::{
    get_postgres_pool, get_redis_client,
    services::{
        hashmap_two_factor_auth_code_store::HashMapTwoFactorAuthCodeStore,
        mock_email_client::MockEmailClient, postgres_user_store::PostgresUserStore,
        redis_banned_token_store::RedisBannedTokenStore,
    },
    utils::constants::{prod::APP_ADDRESS, DATABASE_URL, REDIS_HOST_NAME},
    AppState, Application,
};
use sqlx::PgPool;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let pg_pool = configure_postgresql().await;
    let redis_connection = Arc::new(RwLock::new(configure_redis()));

    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(Arc::clone(
        &redis_connection,
    ))));
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

async fn configure_postgresql() -> PgPool {
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool");

    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}
