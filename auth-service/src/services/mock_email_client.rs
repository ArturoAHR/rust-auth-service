use color_eyre::eyre::Result;
use secrecy::ExposeSecret;
use tracing::debug;

use crate::domain::{parse::Email, EmailClient};

pub struct MockEmailClient;

#[async_trait::async_trait]
impl EmailClient for MockEmailClient {
    async fn send_email(&self, recipient: &Email, subject: &str, content: &str) -> Result<()> {
        debug!(
            "Sending email to {} with subject: {} and content: {}",
            recipient.as_ref().expose_secret(),
            subject,
            content
        );

        Ok(())
    }
}
