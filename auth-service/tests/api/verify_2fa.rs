use serde_json::json;
use uuid::Uuid;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let login_attempt_id = Uuid::new_v4();

    let test_cases = vec![
        json!({"email": random_email, "loginAttemptId":  login_attempt_id }),
        json!({"email": random_email, "2FACode": "123456"}),
        json!({"loginAttemptId": login_attempt_id, "2FACode": "123456"}),
    ];

    for test_case in test_cases {
        let response = app.post_verify_2fa(&test_case).await;

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
    let login_attempt_id = Uuid::new_v4();

    let test_cases = vec![
        json!({"email": "",  "loginAttemptId":  login_attempt_id, "2FACode": "123456"}),
        json!({"email": "invalid-email",  "loginAttemptId":  login_attempt_id, "2FACode": "123456"}),
        json!({"email": random_email,  "loginAttemptId":  "invalid-uuid", "2FACode": "123456"}),
        json!({"email": random_email,  "loginAttemptId":  login_attempt_id, "2FACode": "123"}),
    ];

    for test_case in test_cases {
        let response = app.post_verify_2fa(&test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input {:?}",
            test_case
        );
    }
}
