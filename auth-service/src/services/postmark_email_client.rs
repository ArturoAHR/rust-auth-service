use axum::http::request;
use color_eyre::eyre::Result;
use reqwest::{Client, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use tracing::instrument;

use crate::domain::{parse::Email, EmailClient};

const MESSAGE_STREAM: &str = "outbound";
const POSTMARK_AUTH_HEADER: &str = "X-Postmark-Server-Token";

pub struct PostmarkEmailClient {
    http_client: Client,
    base_url: String,
    sender: Email,
    access_token: SecretString,
}

impl PostmarkEmailClient {
    fn new(
        base_url: String,
        sender: Email,
        access_token: SecretString,
        http_client: Client,
    ) -> Self {
        Self {
            base_url,
            sender,
            access_token,
            http_client,
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct SendEmailRequest<'a> {
    from: &'a str,
    to: &'a str,
    subject: &'a str,
    html_body: &'a str,
    text_body: &'a str,
    message_stream: &'a str,
}

#[async_trait::async_trait]
impl EmailClient for PostmarkEmailClient {
    #[instrument(name = "Sending email", skip_all)]
    async fn send_email(&self, recipient: &Email, subject: &str, content: &str) -> Result<()> {
        let base = Url::parse(&self.base_url)?;
        let url = base.join("/email")?;

        let request_body = SendEmailRequest {
            from: self.sender.as_ref().expose_secret(),
            to: recipient.as_ref().expose_secret(),
            subject,
            html_body: content,
            text_body: content,
            message_stream: MESSAGE_STREAM,
        };

        let request = self
            .http_client
            .post(url)
            .header(POSTMARK_AUTH_HEADER, self.access_token.expose_secret())
            .json(&request_body);

        request.send().await?.error_for_status()?;

        Ok(())
    }
}
