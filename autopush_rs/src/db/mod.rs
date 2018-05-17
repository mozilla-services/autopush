use std::collections::HashSet;
use std::env;
use std::rc::Rc;
use uuid::Uuid;

use cadence::{Counted, StatsdClient};
use futures::{future, Future};
use futures_backoff::retry_if;
use rusoto_core::reactor::RequestDispatcher;
use rusoto_core::Region;
use rusoto_credential::StaticProvider;
use rusoto_dynamodb::{
    AttributeValue, BatchWriteItemError, BatchWriteItemInput, DeleteItemError, DeleteItemInput,
    DynamoDb, DynamoDbClient, PutRequest, UpdateItemError, UpdateItemInput, UpdateItemOutput,
    WriteRequest,
};
use serde_dynamodb;

#[macro_use]
mod macros;
mod commands;
mod models;
use errors::*;
use protocol::Notification;
use server::Server;
mod util;
use util::timing::sec_since_epoch;

use self::commands::FetchMessageResponse;
use self::models::{DynamoDbNotification, DynamoDbUser};

const MAX_EXPIRY: u64 = 2592000;
const USER_RECORD_VERSION: u8 = 1;

/// Basic requirements for notification content to deliver to websocket client
// - channelID  (the subscription website intended for)
// - version    (only really utilized for notification acknowledgement in
//               webpush, used to be the sole carrier of data, can now be anything)
// - data       (encrypted content)
// - headers    (hash of crypto headers: encoding, encrypption, crypto-key, encryption-key)
#[derive(Default, Clone)]
pub struct HelloResponse {
    pub uaid: Option<Uuid>,
    pub message_month: String,
    pub check_storage: bool,
    pub reset_uaid: bool,
    pub rotate_message_table: bool,
    pub connected_at: u64,
}

pub struct CheckStorageResponse {
    pub include_topic: bool,
    pub messages: Vec<Notification>,
    pub timestamp: Option<u64>,
}

pub enum RegisterResponse {
    Success { endpoint: String },

    Error { error_msg: String, status: u32 },
}

pub struct DynamoStorage {
    ddb: Rc<Box<DynamoDb>>,
}

impl DynamoStorage {
    pub fn new() -> DynamoStorage {
        let ddb: Box<DynamoDb> = if let Ok(endpoint) = env::var("AWS_LOCAL_DYNAMODB") {
            Box::new(DynamoDbClient::new(
                RequestDispatcher::default(),
                StaticProvider::new_minimal("BogusKey".to_string(), "BogusKey".to_string()),
                Region::Custom {
                    name: "us-east-1".to_string(),
                    endpoint,
                },
            ))
        } else {
            Box::new(DynamoDbClient::simple(Region::default()))
        };
        DynamoStorage { ddb: Rc::new(ddb) }
    }

    pub fn increment_storage(
        &self,
        table_name: &str,
        uaid: &Uuid,
        timestamp: &str,
    ) -> MyFuture<UpdateItemOutput> {
        let ddb = self.ddb.clone();
        let expiry = sec_since_epoch() + 2 * MAX_EXPIRY;
        let attr_values = hashmap! {
            ":timestamp".to_string() => val!(N => timestamp),
            ":expiry".to_string() => val!(N => expiry),
        };
        let update_input = UpdateItemInput {
            key: ddb_item! {
                uaid: s => uaid.simple().to_string(),
                chidmessageid: s => " ".to_string()
            },
            update_expression: Some("SET current_timestamp=:timestamp, expiry=:expiry".to_string()),
            expression_attribute_values: Some(attr_values),
            table_name: table_name.to_string(),
            ..Default::default()
        };
        let ddb_response = retry_if(
            move || ddb.update_item(&update_input),
            |err: &UpdateItemError| {
                matches!(err, &UpdateItemError::ProvisionedThroughputExceeded(_))
            },
        ).chain_err(|| "Error incrementing storage");
        Box::new(ddb_response)
    }

    pub fn hello(
        &self,
        connected_at: &u64,
        uaid: Option<&Uuid>,
        router_table_name: &str,
        router_url: &str,
        message_table_names: &Vec<String>,
        metrics: &StatsdClient,
    ) -> MyFuture<HelloResponse> {
        let router_table_name = router_table_name.to_string();
        let ddb = self.ddb.clone();
        let cur_month = message_table_names.last().unwrap().clone();
        let response: MyFuture<(HelloResponse, Option<DynamoDbUser>)> = if let Some(uaid) = uaid {
            commands::lookup_user(
                ddb,
                &uaid,
                connected_at,
                router_url,
                &router_table_name,
                message_table_names,
                metrics,
            )
        } else {
            Box::new(future::ok((
                HelloResponse {
                    message_month: cur_month,
                    ..Default::default()
                },
                None,
            )))
        };
        let ddb = self.ddb.clone();
        let router_url = router_url.to_string();
        let connected_at = connected_at.clone();
        let response = response.and_then(move |(mut hello_response, user_opt)| -> MyFuture<_> {
            let hello_message_month = hello_response.message_month.clone();
            let user = user_opt.unwrap_or_else(|| DynamoDbUser {
                current_month: Some(hello_message_month),
                node_id: Some(router_url),
                connected_at: connected_at,
                ..Default::default()
            });
            let uaid = user.uaid.clone();
            let mut err_response = hello_response.clone();
            err_response.connected_at = connected_at;
            let ddb_response = commands::register_user(ddb, &user, router_table_name.as_ref())
                .and_then(move |result| {
                    debug!("Success adding user, item output: {:?}", result);
                    hello_response.uaid = Some(uaid);
                    future::ok(hello_response)
                })
                .or_else(move |e| {
                    debug!("Error registering user: {:?}", e);
                    future::ok(err_response)
                });
            Box::new(ddb_response)
        });
        metrics.incr("ua.command.hello").ok();
        Box::new(response)
    }

    pub fn register(
        &self,
        srv: Rc<Server>,
        uaid: &Uuid,
        channel_id: &Uuid,
        message_month: &str,
        key: Option<String>,
    ) -> MyFuture<RegisterResponse> {
        let ddb = self.ddb.clone();
        let endpoint = match srv.make_endpoint(uaid, channel_id, key) {
            Ok(result) => result,
            Err(_) => {
                return Box::new(future::ok(RegisterResponse::Error {
                    error_msg: "Failed to generate endpoint".to_string(),
                    status: 400,
                }))
            }
        };
        let mut chids = HashSet::new();
        chids.insert(channel_id.hyphenated().to_string());
        let response = commands::save_channels(ddb, uaid, chids, message_month)
            .and_then(move |_| -> MyFuture<_> {
                Box::new(future::ok(RegisterResponse::Success { endpoint }))
            })
            .or_else(move |_| -> MyFuture<_> {
                Box::new(future::ok(RegisterResponse::Error {
                    status: 503,
                    error_msg: "Failed to register channel".to_string(),
                }))
            });
        Box::new(response)
    }

    pub fn drop_uaid(&self, table_name: &str, uaid: &Uuid) -> MyFuture<()> {
        let ddb = self.ddb.clone();
        let response = commands::drop_user(ddb, uaid, table_name)
            .and_then(move |_| -> MyFuture<_> { Box::new(future::ok(())) })
            .chain_err(|| "Unable to drop user record");
        Box::new(response)
    }

    pub fn unregister(
        &self,
        uaid: &Uuid,
        channel_id: &Uuid,
        message_month: &str,
        code: u32,
        metrics: &StatsdClient,
    ) -> MyFuture<bool> {
        let ddb = self.ddb.clone();
        let response = commands::unregister_channel_id(ddb, uaid, channel_id, message_month)
            .and_then(move |_| -> MyFuture<_> { Box::new(future::ok(true)) })
            .or_else(move |_| -> MyFuture<_> { Box::new(future::ok(false)) });
        metrics
            .incr_with_tags("ua.command.unregister")
            .with_tag("code", &code.to_string())
            .send()
            .ok();
        Box::new(response)
    }

    /// Migrate a user to a new month table
    pub fn migrate_user(
        &self,
        uaid: &Uuid,
        message_month: &str,
        current_message_month: &str,
        router_table_name: &str,
    ) -> MyFuture<()> {
        let ddb = self.ddb.clone();
        let ddb1 = self.ddb.clone();
        let ddb2 = self.ddb.clone();
        let uaid = uaid.clone();
        let cur_month = current_message_month.to_string();
        let cur_month1 = cur_month.clone();
        let cur_month2 = cur_month.clone();
        let router_table_name = router_table_name.to_string();
        let response = commands::all_channels(ddb, &uaid, message_month)
            .and_then(move |channels| -> MyFuture<_> {
                if channels.is_empty() {
                    Box::new(future::ok(()))
                } else {
                    commands::save_channels(ddb1, &uaid, channels, &cur_month1)
                }
            })
            .and_then(move |_| -> MyFuture<_> {
                commands::update_user_message_month(ddb2, &uaid, &router_table_name, &cur_month2)
            })
            .and_then(move |_| -> MyFuture<_> { Box::new(future::ok(())) })
            .chain_err(|| "Unable to migrate user");
        Box::new(response)
    }

    /// Store a batch of messages when shutting down
    pub fn store_messages(
        &self,
        uaid: &Uuid,
        message_month: &str,
        messages: Vec<Notification>,
    ) -> MyFuture<()> {
        let ddb = self.ddb.clone();
        let put_items: Vec<WriteRequest> = messages
            .into_iter()
            .filter_map(|mut n| {
                n.uaid = Some(uaid.simple().to_string());
                DynamoDbNotification::from_notif(n)
                    .map(|notif| serde_dynamodb::to_hashmap(&notif).ok())
                    .unwrap_or_default()
            })
            .map(|hm| WriteRequest {
                put_request: Some(PutRequest { item: hm }),
                delete_request: None,
            })
            .collect();
        let batch_input = BatchWriteItemInput {
            request_items: hashmap! { message_month.to_string() => put_items },
            ..Default::default()
        };
        let response = retry_if(
            move || ddb.batch_write_item(&batch_input),
            |err: &BatchWriteItemError| {
                matches!(err, &BatchWriteItemError::ProvisionedThroughputExceeded(_))
            },
        )
        .and_then(|_| Box::new(future::ok(())))
            .map_err(|err| {
                debug!("Error saving notification: {:?}", err);
                err
            })
            // TODO: Use Sentry to capture/report this error
            .chain_err(|| "Error saving notifications");
        Box::new(response)
    }

    /// Delete a given notification from the database
    ///
    /// No checks are done to see that this message came from the database or has
    /// sufficient properties for a delete as that is expected to have been done
    /// before this is called. In the event information is missing, a future::ok
    /// is returned.
    pub fn delete_message(&self, table_name: &str, notif: Notification) -> MyFuture<()> {
        let ddb = self.ddb.clone();
        let uaid = if let Some(ref uaid) = notif.uaid {
            uaid.clone()
        } else {
            return Box::new(future::ok(()));
        };
        let chidmessageid = notif.sort_key();
        let delete_input = DeleteItemInput {
            table_name: table_name.to_string(),
            key: ddb_item! {
               uaid: s => uaid,
               chidmessageid: s => chidmessageid
            },
            ..Default::default()
        };
        let response = retry_if(
            move || ddb.delete_item(&delete_input),
            |err: &DeleteItemError| {
                matches!(err, &DeleteItemError::ProvisionedThroughputExceeded(_))
            },
        ).and_then(|_| Box::new(future::ok(())))
            .chain_err(|| "Error deleting notification");
        Box::new(response)
    }

    pub fn check_storage(
        &self,
        table_name: &str,
        uaid: &Uuid,
        include_topic: bool,
        timestamp: Option<u64>,
    ) -> MyFuture<CheckStorageResponse> {
        let ddb = self.ddb.clone();
        let response: MyFuture<FetchMessageResponse> = if include_topic {
            commands::fetch_messages(ddb, table_name, uaid, 11 as u32)
        } else {
            Box::new(future::ok(Default::default()))
        };
        let uaid = uaid.clone();
        let table_name = table_name.to_string();
        let ddb2 = self.ddb.clone();
        let response = response.and_then(move |resp| {
            // Return now from this future if we have messages
            if !resp.messages.is_empty() {
                debug!("Topic message returns: {:?}", resp.messages);
                return future::Either::A(future::ok(CheckStorageResponse {
                    include_topic: true,
                    messages: resp.messages,
                    timestamp: resp.timestamp,
                }));
            }
            // Use the timestamp returned by the topic query if we were looking at the topics
            let timestamp = if include_topic {
                resp.timestamp
            } else {
                timestamp
            };
            let next_query = {
                if resp.messages.is_empty() || resp.timestamp.is_some() {
                    commands::fetch_timestamp_messages(
                        ddb2,
                        table_name.as_ref(),
                        &uaid,
                        timestamp,
                        10 as u32,
                    )
                } else {
                    Box::new(future::ok(Default::default()))
                }
            };
            let next_query = next_query.and_then(move |resp: FetchMessageResponse| {
                // If we didn't get a timestamp off the last query, use the original
                // value if passed one
                let timestamp = resp.timestamp.or(timestamp);
                Ok(CheckStorageResponse {
                    include_topic: false,
                    messages: resp.messages,
                    timestamp,
                })
            });
            future::Either::B(next_query)
        });
        Box::new(response)
    }
}
