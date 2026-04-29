use crate::helpers::TestApp;

#[tokio::test]
async fn sign_up_returns_ok() {
    let app = TestApp::new().await;

    let response = app.post_sign_up().await;

    assert_eq!(response.status().as_u16(), 200);
}
