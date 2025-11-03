use super::models::*;
use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};

pub struct ApiClient {
    base_url: String,
    client: Client,
}

impl ApiClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: Client::new(),
        }
    }

    pub fn create_account(
        &self,
        username: String,
        password: String,
    ) -> Result<CreateAccountResponse> {
        let request = CreateAccountRequest { username, password };

        let response = self
            .client
            .post(format!("{}/api/account/create", self.base_url))
            .header(CONTENT_TYPE, "application/json")
            .json(&request)
            .send()?;

        if response.status().is_success() {
            Ok(response.json()?)
        } else {
            let error: ErrorResponse = response.json().unwrap_or(ErrorResponse {
                error: "Unknown error occurred".to_string(),
            });
            Err(anyhow!("Failed to create account: {}", error.error))
        }
    }

    pub fn send_message(
        &self,
        token: &str,
        to_username: String,
        content: String,
    ) -> Result<SendMessageResponse> {
        let request = SendMessageRequest {
            to_username,
            content,
        };

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token))?,
        );

        let response = self
            .client
            .post(format!("{}/api/messages/send", self.base_url))
            .headers(headers)
            .json(&request)
            .send()?;

        if response.status().is_success() {
            Ok(response.json()?)
        } else {
            let status = response.status();
            let error: ErrorResponse = response.json().unwrap_or(ErrorResponse {
                error: format!("HTTP {}", status),
            });
            Err(anyhow!("Failed to send message: {}", error.error))
        }
    }

    pub fn get_messages(&self, token: &str) -> Result<Vec<MessageResponse>> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token))?,
        );

        let response = self
            .client
            .get(format!("{}/api/messages", self.base_url))
            .headers(headers)
            .send()?;

        if response.status().is_success() {
            Ok(response.json()?)
        } else {
            let status = response.status();
            let error: ErrorResponse = response.json().unwrap_or(ErrorResponse {
                error: format!("HTTP {}", status),
            });
            Err(anyhow!("Failed to get messages: {}", error.error))
        }
    }

    pub fn get_conversations(&self, token: &str) -> Result<Vec<ConversationResponse>> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token))?,
        );

        let response = self
            .client
            .get(format!("{}/api/conversations", self.base_url))
            .headers(headers)
            .send()?;

        if response.status().is_success() {
            Ok(response.json()?)
        } else {
            let status = response.status();
            let error: ErrorResponse = response.json().unwrap_or(ErrorResponse {
                error: format!("HTTP {}", status),
            });
            Err(anyhow!("Failed to get conversations: {}", error.error))
        }
    }

    pub fn health_check(&self) -> Result<bool> {
        let response = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()?;

        Ok(response.status().is_success())
    }

    pub fn update_username(
        &self,
        token: &str,
        new_username: String,
    ) -> Result<UpdateUsernameResponse> {
        let request = UpdateUsernameRequest { new_username };

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token))?,
        );

        let response = self
            .client
            .post(format!("{}/api/account/update-username", self.base_url))
            .headers(headers)
            .json(&request)
            .send()?;

        if response.status().is_success() {
            Ok(response.json()?)
        } else {
            let status = response.status();
            let error: ErrorResponse = response.json().unwrap_or(ErrorResponse {
                error: format!("HTTP {}", status),
            });
            Err(anyhow!("Failed to update username: {}", error.error))
        }
    }
}
