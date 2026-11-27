//! Android 17 `NotificationSyncRpcService` wire protobufs (`com.google.ambient.streaming`).
//!
//! Field numbers verified directly from Pixel 9 Pro `base.apk` (`lwq`, `lwx`, `lwy`, `lwn`,
//! `lwg`, `lwh`, `lxk`, `lxg`, `lwf`, `lwv.java`, and `lyg.java`).

use prost::Message;
use serde::{Deserialize, Serialize};

/// `lwq`: Streaming notification sync update packet.
#[derive(Clone, PartialEq, Message)]
pub struct NotificationSyncEvent {
    #[prost(oneof = "notification_sync_event::Event", tags = "1, 2, 3, 4")]
    pub event: Option<notification_sync_event::Event>,
}

pub mod notification_sync_event {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Event {
        /// `lxi`: Initial batch of currently active notifications on subscribe.
        #[prost(message, tag = "1")]
        Initial(PostedNotifications),
        /// `lxj`: NotificationListenerService disconnected on phone.
        #[prost(bytes = "vec", tag = "2")]
        ShadeDisconnected(Vec<u8>),
        /// `lwx`: Posted / updated notifications.
        #[prost(message, tag = "3")]
        Posted(PostedNotifications),
        /// `lwy`: Dismissed / removed notification keys.
        #[prost(message, tag = "4")]
        Removed(RemovedNotifications),
    }
}

/// `lwx`: batch of posted/updated notifications.
#[derive(Clone, PartialEq, Message)]
pub struct PostedNotifications {
    #[prost(message, repeated, tag = "1")]
    pub notifications: Vec<SyncedNotification>,
}

/// `lwy`: batch of dismissed notification keys.
#[derive(Clone, PartialEq, Message)]
pub struct RemovedNotifications {
    #[prost(string, repeated, tag = "1")]
    pub keys: Vec<String>,
}

/// `lwn`: Notification payload synced over `NotificationSyncRpcService`.
/// Field tags verified against Pixel 9 Pro Android 17 `base.apk` (`lwn`, `lwi`, `lwl`, `lwd`).
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct SyncedNotification {
    #[prost(int32, optional, tag = "1")]
    pub id: Option<i32>,
    #[prost(string, optional, tag = "2")]
    pub channel_id: Option<String>,
    #[prost(int64, optional, tag = "3")]
    pub post_time_ms: Option<i64>,
    /// `lwi`: Standard notification header/content (`title`, `text`, `sub_text`).
    #[prost(message, optional, tag = "4")]
    pub basic_content: Option<BasicNotificationContent>,
    /// `lwl`: MessagingStyle (Telegram, WhatsApp, Messages, etc.).
    #[prost(message, optional, tag = "5")]
    pub messaging_content: Option<MessagingNotificationContent>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub small_icon_png: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "9")]
    pub large_icon_png: Option<Vec<u8>>,
    /// `lwd`: BigTextStyle expanded content.
    #[prost(message, optional, tag = "10")]
    pub big_text_content: Option<BigTextNotificationContent>,
    #[prost(string, optional, tag = "12")]
    pub package_name: Option<String>,
    #[prost(string, optional, tag = "13")]
    pub app_name: Option<String>,
    /// `StatusBarNotification.getKey()` (`lwn.o`), used for `ExecuteRemoteAction` Dismiss / Reply.
    #[prost(string, optional, tag = "14")]
    pub key: Option<String>,
    #[prost(bool, optional, tag = "17")]
    pub is_ongoing: Option<bool>,
    #[prost(bool, optional, tag = "18")]
    pub is_group_summary: Option<bool>,
    #[prost(bool, optional, tag = "19")]
    pub is_dismissible: Option<bool>,
}

/// `lwl`: MessagingStyle content (`conversation_title`, `user`, `is_group`, `messages`).
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct MessagingNotificationContent {
    #[prost(string, optional, tag = "1")]
    pub conversation_title: Option<String>,
    #[prost(message, optional, tag = "2")]
    pub user: Option<MessagingPerson>,
    #[prost(bool, optional, tag = "3")]
    pub is_group: Option<bool>,
    #[prost(message, repeated, tag = "4")]
    pub messages: Vec<MessagingMessage>,
}

/// `lwk`: Single message inside `MessagingStyle`.
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct MessagingMessage {
    #[prost(message, optional, tag = "1")]
    pub sender: Option<MessagingPerson>,
    #[prost(string, optional, tag = "2")]
    pub text: Option<String>,
    #[prost(int64, optional, tag = "3")]
    pub timestamp_ms: Option<i64>,
}

/// `lxb`: Person sender metadata.
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct MessagingPerson {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
}

/// `lwi`: Standard notification metadata & text content (`lxp.java:524-605`).
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct BasicNotificationContent {
    #[prost(string, optional, tag = "1")]
    pub channel_group_id: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub info_text: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub tag: Option<String>,
    #[prost(string, optional, tag = "7")]
    pub sub_text: Option<String>,
    #[prost(string, optional, tag = "8")]
    pub text: Option<String>,
    #[prost(string, optional, tag = "9")]
    pub title: Option<String>,
}

/// `lwd`: BigTextStyle expanded text (`lxp.java:215-248`).
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct BigTextNotificationContent {
    #[prost(string, optional, tag = "1")]
    pub big_text: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub big_title: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub summary_text: Option<String>,
}

/// `lwg.java`: `NotificationSyncRpcService.ExecuteRemoteAction` request.
#[derive(Clone, PartialEq, Message)]
pub struct ExecuteRemoteActionRequest {
    #[prost(string, optional, tag = "1")]
    pub notification_key: Option<String>,
    #[prost(oneof = "execute_remote_action_request::Action", tags = "2, 3, 4")]
    pub action: Option<execute_remote_action_request::Action>,
}

pub mod execute_remote_action_request {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Action {
        /// `lxk`: Tap action button by index (`notification.actions[action_index]`).
        #[prost(message, tag = "2")]
        TapAction(TapAction),
        /// `lxg`: Inline Quick Reply (`RemoteInput` free-form text + `action_index`).
        #[prost(message, tag = "3")]
        QuickReply(QuickReplyAction),
        /// `lwf`: Dismiss notification on the phone.
        #[prost(message, tag = "4")]
        Dismiss(DismissAction),
    }
}

/// `lxk`: action button index.
#[derive(Clone, PartialEq, Message)]
pub struct TapAction {
    #[prost(int32, optional, tag = "1")]
    pub action_index: Option<i32>,
}

/// `lxg`: inline quick reply text + action button index (`lyg.java:224-247`).
#[derive(Clone, PartialEq, Message)]
pub struct QuickReplyAction {
    #[prost(string, optional, tag = "1")]
    pub reply_text: Option<String>,
    #[prost(int32, optional, tag = "2")]
    pub action_index: Option<i32>,
}

/// `lwf`: dismiss notification.
#[derive(Clone, PartialEq, Message)]
pub struct DismissAction {}

/// `lwh.java`: `ExecuteRemoteAction` response (`1 = SUCCESS`, `5 = FAILED`).
#[derive(Clone, PartialEq, Message)]
pub struct ExecuteRemoteActionResponse {
    #[prost(int32, optional, tag = "1")]
    pub status: Option<i32>,
}

pub fn build_quick_reply(notification_key: &str, action_index: i32, reply_text: &str) -> Vec<u8> {
    ExecuteRemoteActionRequest {
        notification_key: Some(notification_key.to_string()),
        action: Some(execute_remote_action_request::Action::QuickReply(
            QuickReplyAction {
                reply_text: Some(reply_text.to_string()),
                action_index: Some(action_index),
            },
        )),
    }
    .encode_to_vec()
}

pub fn build_dismiss(notification_key: &str) -> Vec<u8> {
    ExecuteRemoteActionRequest {
        notification_key: Some(notification_key.to_string()),
        action: Some(execute_remote_action_request::Action::Dismiss(
            DismissAction {},
        )),
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_reply_and_notification_roundtrip() {
        let wire = build_quick_reply("0|com.whatsapp|42|null|10234", 0, "On my way!");
        let req = ExecuteRemoteActionRequest::decode(wire.as_slice()).unwrap();
        assert_eq!(req.notification_key.as_deref(), Some("0|com.whatsapp|42|null|10234"));
        match req.action.unwrap() {
            execute_remote_action_request::Action::QuickReply(qr) => {
                assert_eq!(qr.reply_text.as_deref(), Some("On my way!"));
                assert_eq!(qr.action_index, Some(0));
            }
            _ => panic!("expected quick reply"),
        }
    }
}
