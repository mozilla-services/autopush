//! Definition of WebSocket protocol messages
//!
//! This module is a structured definition of the WebSocket protocol. Both
//! messages received from the client and messages sent from the server are
//! defined here. The `derive(Deserialize)` and `derive(Serialize)` annotations
//! are used to generate the ability to serialize these structures to JSON,
//! using the `serde` crate. More docs for serde can be found at
//! https://serde.rs

use uuid::Uuid;

#[derive(Deserialize)]
#[serde(tag = "messageType", rename_all = "lowercase")]
pub enum ClientMessage {
    Hello {
        uaid: Option<Uuid>,
        #[serde(rename = "channelIDs", skip_serializing_if = "Option::is_none")]
        channel_ids: Option<Vec<Uuid>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        use_webpush: Option<bool>,
    },

    Register {
        #[serde(rename = "channelID")]
        channel_id: Uuid,
    },

    Unregister {
        #[serde(rename = "channelID")]
        channel_id: Uuid,
    },

    Ack {
        updates: Vec<ClientAck>,
    },
}

#[derive(Deserialize)]
pub struct ClientAck {
    #[serde(rename = "channelID")]
    pub channel_id: Uuid,
    pub version: String,
}

#[derive(Serialize)]
#[serde(tag = "messageType", rename_all = "lowercase")]
pub enum ServerMessage {
    Hello {
        uaid: Uuid,
        status: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        use_webpush: Option<bool>,
    },

    Register {
        #[serde(rename = "channelID")]
        channel_id: Uuid,
        status: u32,
        #[serde(rename = "pushEndpoint")]
        push_endpoint: String,
    },

    Unregister {
        #[serde(rename = "channelID")]
        channel_id: Uuid,
        status: u32,
    },

    Notification(Notification),
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum Notification {
    Simple {
        updates: Vec<Update>,
    },

    WebPush {
        #[serde(rename = "channelID")]
        channel_id: Uuid,
        version: String,
    },
}

#[derive(Serialize)]
pub struct Update {
    #[serde(rename = "channelID")]
    pub channel_id: Uuid,
    pub version: u64,
}
