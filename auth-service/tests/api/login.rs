use auth_service::ErrorResponse;
use serde_json::json;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        json!({
            "password": "password123",
        }),
        json!({
            "email": random_email,
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        json!({
            "email": "",
            "password": "password123",
        }),
        json!({
            "email": "invalid-email",
            "password": "password123",
        }),
        json!({
            "email": random_email,
            "password": "1234567",
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input {:?}",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to Error Response")
                .error,
            "Invalid credentials".to_owned()
        )
    }
}
