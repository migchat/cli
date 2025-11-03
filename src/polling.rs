use crate::api::ApiClient;
#[cfg(target_os = "linux")]
use notify_rust::Notification;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const POLL_INTERVAL_SECS: u64 = 10;

#[cfg(not(target_os = "linux"))]
fn send_notification(_from: &str, _content: &str) {
    // Notifications only supported on Linux currently
}

#[cfg(target_os = "linux")]
fn send_notification(from: &str, content: &str) {
    let _ = Notification::new()
        .summary("New MigChat Message")
        .body(&format!("From {}: {}", from, content))
        .timeout(5000)
        .show();
}

pub struct MessagePoller {
    should_stop: Arc<Mutex<bool>>,
    seen_message_ids: Arc<Mutex<HashSet<i64>>>,
}

impl MessagePoller {
    pub fn new() -> Self {
        Self {
            should_stop: Arc::new(Mutex::new(false)),
            seen_message_ids: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn start(&self, server_url: String, token: String, username: String) {
        let should_stop = Arc::clone(&self.should_stop);
        let seen_ids = Arc::clone(&self.seen_message_ids);

        thread::spawn(move || {
            let api = ApiClient::new(server_url);

            loop {
                // Check if we should stop
                if *should_stop.lock().unwrap() {
                    break;
                }

                // Poll for new messages
                if let Ok(messages) = api.get_messages(&token) {
                    let mut seen = seen_ids.lock().unwrap();

                    for msg in messages {
                        // Only notify about messages TO the current user that we haven't seen
                        if msg.to_username == username && !seen.contains(&msg.id) {
                            // Send notification
                            send_notification(&msg.from_username, &msg.content);
                            seen.insert(msg.id);
                        } else if !seen.contains(&msg.id) {
                            // Mark as seen even if it's a sent message
                            seen.insert(msg.id);
                        }
                    }
                }

                // Wait before polling again
                thread::sleep(Duration::from_secs(POLL_INTERVAL_SECS));
            }
        });
    }

    pub fn stop(&self) {
        *self.should_stop.lock().unwrap() = true;
    }
}

impl Drop for MessagePoller {
    fn drop(&mut self) {
        self.stop();
    }
}
