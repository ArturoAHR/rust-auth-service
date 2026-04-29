use auth_service::Application;
use reqwest::{Client, Response};

pub struct TestApp {
    pub address: String,
    pub client: Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let app = Application::build("127.0.0.1:0")
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        let _ = tokio::spawn(app.run());

        let client = Client::new();

        TestApp { address, client }
    }

    pub async fn get_root(&self) -> Response {
        self.client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn sign_up(&self) -> Response {
        self.client
            .post(&format!("{}/signup", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn login(&self) -> Response {
        self.client
            .post(&format!("{}/login", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn verify_2fa(&self) -> Response {
        self.client
            .post(&format!("{}/verify-2fa", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn logout(&self) -> Response {
        self.client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn verify_token(&self) -> Response {
        self.client
            .post(&format!("{}/verify-token", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }
}
