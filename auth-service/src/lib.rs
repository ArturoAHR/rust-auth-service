use std::{error::Error, sync::Arc};

use axum::{routing::post, serve::Serve, Router};
use tokio::{net::TcpListener, sync::RwLock};
use tower_http::services::ServeDir;

use crate::services::hashmap_user_store::HashMapUserStore;

pub mod domain;
pub mod routes;
pub mod services;

pub type AppStateUserStore = Arc<RwLock<HashMapUserStore>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: AppStateUserStore,
}

impl AppState {
    pub fn new(user_store: AppStateUserStore) -> Self {
        Self { user_store }
    }
}

pub struct Application {
    server: Serve<TcpListener, Router, Router>,

    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        let assets_dir = ServeDir::new("assets");
        let router = Router::new()
            .fallback_service(assets_dir)
            .route("/signup", post(routes::sign_up))
            .route("/login", post(routes::login))
            .route("/verify-2fa", post(routes::verify_2fa))
            .route("/logout", post(routes::logout))
            .route("/verify-token", post(routes::verify_token))
            .with_state(app_state);

        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("Listening on {}", &self.address);
        self.server.await
    }
}
