/// DynamoDB Client helpers
use std::env;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::result::Result as StdResult;
use uuid::Uuid;

use cadence::{Counted, StatsdClient};
use chrono::Utc;
use futures::Future;
use futures::future;
use futures_backoff::retry_if;
use rand;
use rand::distributions::{IndependentSample, Range};
use regex::RegexSet;
use rusoto_core::Region;
use rusoto_core::reactor::RequestDispatcher;
use rusoto_credential::StaticProvider;
use rusoto_dynamodb::{AttributeValue, DeleteItemError, DeleteItemInput, DeleteItemOutput,
                      DynamoDb, DynamoDbClient, GetItemError, GetItemInput, GetItemOutput,
                      PutItemError, PutItemInput, PutItemOutput, QueryError, QueryInput,
                      UpdateItemError, UpdateItemInput, UpdateItemOutput};
use serde::Serializer;
use serde_dynamodb;

use protocol::Notification;
use server::Server;
use errors::*;
use util::timing::{ms_since_epoch, sec_since_epoch};

const MAX_EXPIRY: u64 = 2592000;
const USER_RECORD_VERSION: u8 = 1;

/// A bunch of macro helpers from rusoto_helpers code, which they pulled from crates.io because
/// they were waiting for rusuto to hit 1.0.0 or something. For sanity, they are instead accumulated
/// here for our use.
#[allow(unused_macros)]
macro_rules! attributes {
    ($($val:expr => $attr_type:expr),*) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push(AttributeDefinition {
                    attribute_name: String::from($val),
                    attribute_type: String::from($attr_type)
                });
            )*
            temp_vec
        }
    }
}

#[allow(unused_macros)]
macro_rules! key_schema {
    ($($name:expr => $key_type:expr),*) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push(KeySchemaElement {
                    key_type: String::from($key_type),
                    attribute_name: String::from($name)
                });
            )*
            temp_vec
        }
    }
}

macro_rules! val {
	(B => $val:expr) => (
	    {
	    	let mut attr = AttributeValue::default();
	    	attr.b = Some($val);
	    	attr
	    }
	);
	(S => $val:expr) => (
	    {
			let mut attr = AttributeValue::default();
			attr.s = Some($val.to_string());
			attr
		}
	);
	(SS => $val:expr) => (
	    {
			let mut attr = AttributeValue::default();
			let vals: Vec<String> = $val.iter()
			    .map(|v| v.to_string())
			    .collect();
			attr.ss = Some(vals);
			attr
		}
	);
	(N => $val:expr) => (
	    {
	    	let mut attr = AttributeValue::default();
	    	attr.n = Some($val.to_string());
	    	attr
	    }
	);
}

/// Create a **HashMap** from a list of key-value pairs
///
/// ## Example
///
/// ```
/// #[macro_use] extern crate rusoto_helpers;
/// # fn main() {
///
/// let map = hashmap!{
///     "a" => 1,
///     "b" => 2,
/// };
/// assert_eq!(map["a"], 1);
/// assert_eq!(map["b"], 2);
/// assert_eq!(map.get("c"), None);
/// # }
/// ```
macro_rules! hashmap {
    (@single $($x:tt)*) => (());
    (@count $($rest:expr),*) => (<[()]>::len(&[$(hashmap!(@single $rest)),*]));

    ($($key:expr => $value:expr,)+) => { hashmap!($($key => $value),+) };
    ($($key:expr => $value:expr),*) => {
        {
            let _cap = hashmap!(@count $($key),*);
            let mut _map = ::std::collections::HashMap::with_capacity(_cap);
            $(
                _map.insert($key, $value);
            )*
            _map
        }
    };
}

/// Shorthand for specifying a dynamodb item
macro_rules! ddb_item {
    ($($p:tt: $t:tt => $x:expr),*) => {
        {
            use rusoto_dynamodb::AttributeValue;
            hashmap!{
                $(
                    String::from(stringify!($p)) => AttributeValue {
                        $t: Some($x),
                        ..Default::default()
                    },
                )*
            }
        }
    }
}

/// Custom Uuid serializer
///
/// Serializes a Uuid as a simple string instead of hyphenated
fn uuid_serializer<S>(x: &Uuid, s: S) -> StdResult<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&x.simple().to_string())
}

/// Direct representation of a DynamoDB Notification as we store it in the database
/// Most attributes are optional
#[derive(Default, Deserialize, PartialEq, Debug, Clone, Serialize)]
pub struct NotificationHeaders {
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,
}

fn insert_to_map(map: &mut HashMap<String, String>, name: &str, val: Option<String>) {
    if let Some(val) = val {
        map.insert(name.to_string(), val);
    }
}

impl From<NotificationHeaders> for HashMap<String, String> {
    fn from(val: NotificationHeaders) -> HashMap<String, String> {
        let mut map = HashMap::new();
        insert_to_map(&mut map, "crypto_key", val.crypto_key);
        insert_to_map(&mut map, "encryption", val.encryption);
        insert_to_map(&mut map, "encryption_key", val.encryption_key);
        insert_to_map(&mut map, "encoding", val.encoding);
        map
    }
}

/// Generate a last_connect
///
/// This intentionally generates a limited set of keys for each month in a
//  known sequence. For each month, there's 24 hours * 10 random numbers for
//  a total of 240 keys per month depending on when the user migrates forward.
fn generate_last_connect() -> u64 {
    let today = Utc::now();
    let mut rng = rand::thread_rng();
    let between = Range::new(0, 10);
    let num = between.ind_sample(&mut rng);
    let val = format!("{}{:04}", today.format("%Y%m%H"), num);
    val.parse::<u64>().unwrap()
}

/// Indicate whether this last_connect falls in the current month
fn has_connected_this_month(user: &DynamoDbUser) -> bool {
    user.last_connect
        .map(|v| {
            let pat = Utc::now().format("%Y%m").to_string();
            v.to_string().starts_with(&pat)
        })
        .unwrap_or(false)
}

#[derive(Deserialize, PartialEq, Debug, Clone, Serialize)]
pub struct DynamoDbUser {
    // DynamoDB <Hash key>
    #[serde(serialize_with = "uuid_serializer")]
    uaid: Uuid,
    // Time in milliseconds that the user last connected at
    connected_at: u64,
    // Router type of the user
    router_type: String,
    // Keyed time in a month the user last connected at with limited key range for indexing
    #[serde(skip_serializing_if = "Option::is_none")]
    last_connect: Option<u64>,
    // Last node/port the client was or may be connected to
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<String>,
    // Record version
    #[serde(skip_serializing_if = "Option::is_none")]
    record_version: Option<u8>,
    // Current month table in the database the user is on
    #[serde(skip_serializing_if = "Option::is_none")]
    current_month: Option<String>,
}

impl Default for DynamoDbUser {
    fn default() -> Self {
        DynamoDbUser {
            uaid: Uuid::new_v4(),
            connected_at: ms_since_epoch(),
            router_type: "webpush".to_string(),
            last_connect: Some(generate_last_connect()),
            node_id: None,
            record_version: Some(USER_RECORD_VERSION),
            current_month: None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct DynamoDbNotification {
    // DynamoDB <Hash key>
    #[serde(serialize_with = "uuid_serializer")]
    uaid: Uuid,
    // DynamoDB <Range key>
    // Format:
    //    Topic Messages:
    //        01:{channel id}:{topic}
    //    New Messages:
    //        02:{timestamp int in microseconds}:{channel id}
    chidmessageid: String,
    // Magic entry stored in the first Message record that indicates the highest
    // non-topic timestamp we've read into
    #[serde(skip_serializing_if = "Option::is_none")]
    current_timestamp: Option<u64>,
    // Magic entry stored in the first Message record that indicates the valid
    // channel id's
    #[serde(skip_serializing)]
    chids: Option<HashSet<String>>,
    // Time in seconds from epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<u32>,
    // DynamoDB expiration timestamp per
    //    https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html
    expiry: u32,
    // TTL value provided by application server for the message
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<NotificationHeaders>,
    // This is the acknowledgement-id used for clients to ack that they have received the
    // message. Some Python code refers to this as a message_id. Endpoints generate this
    // value before sending it to storage or a connection node.
    #[serde(skip_serializing_if = "Option::is_none")]
    updateid: Option<String>,
}

struct RangeKey {
    channel_id: Uuid,
    topic: Option<String>,
    sortkey_timestamp: Option<u64>,
    legacy_version: Option<String>,
}

fn parse_sort_key(key: &str) -> Result<RangeKey> {
    lazy_static! {
        static ref RE: RegexSet = RegexSet::new(&[
            r"^01:\S+:\S+$",
            r"^02:\d+:\S+$",
            r"^\S{3,}:\S+$",
        ]).unwrap();
    }
    if !RE.is_match(key) {
        return Err("Invalid chidmessageid".into()).into();
    }

    let v: Vec<&str> = key.split(":").collect();
    match v[0] {
        "01" => {
            if v.len() != 3 {
                return Err("Invalid topic key".into());
            }
            let (channel_id, topic) = (v[1], v[2]);
            let channel_id = Uuid::parse_str(channel_id)?;
            Ok(RangeKey {
                channel_id,
                topic: Some(topic.to_string()),
                sortkey_timestamp: None,
                legacy_version: None,
            })
        }
        "02" => {
            if v.len() != 3 {
                return Err("Invalid topic key".into());
            }
            let (sortkey, channel_id) = (v[1], v[2]);
            let channel_id = Uuid::parse_str(channel_id)?;
            Ok(RangeKey {
                channel_id,
                topic: None,
                sortkey_timestamp: Some(sortkey.parse()?),
                legacy_version: None,
            })
        }
        _ => {
            if v.len() != 2 {
                return Err("Invalid topic key".into());
            }
            let (channel_id, legacy_version) = (v[0], v[1]);
            let channel_id = Uuid::parse_str(channel_id)?;
            Ok(RangeKey {
                channel_id,
                topic: None,
                sortkey_timestamp: None,
                legacy_version: Some(legacy_version.to_string()),
            })
        }
    }
}

impl DynamoDbNotification {
    fn to_notif(self) -> Result<Notification> {
        let key = parse_sort_key(&self.chidmessageid)?;
        let version = key.legacy_version
            .or(self.updateid)
            .ok_or("No valid updateid/version found")?;

        Ok(Notification {
            uaid: Some(self.uaid.simple().to_string()),
            channel_id: key.channel_id,
            version,
            ttl: self.ttl.ok_or("No TTL found")?,
            timestamp: self.timestamp.ok_or("No timestamp found")?,
            topic: key.topic,
            data: self.data,
            headers: self.headers.map(|m| m.into()),
            sortkey_timestamp: key.sortkey_timestamp,
        })
    }
}

///

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

#[derive(Default)]
pub struct FetchMessageResponse {
    pub timestamp: Option<u64>,
    pub messages: Vec<Notification>,
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
        let expiry = sec_since_epoch() + MAX_EXPIRY;
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

    pub fn fetch_messages(
        ddb: Rc<Box<DynamoDb>>,
        table_name: &str,
        uaid: &Uuid,
        limit: u32,
    ) -> MyFuture<FetchMessageResponse> {
        let attr_values = hashmap! {
            ":uaid".to_string() => val!(S => uaid.simple().to_string()),
            ":cmi".to_string() => val!(S => "02"),
        };
        let query_input = QueryInput {
            key_condition_expression: Some("uaid = :uaid AND chidmessageid < :cmi".to_string()),
            expression_attribute_values: Some(attr_values),
            table_name: table_name.to_string(),
            limit: Some(limit as i64),
            ..Default::default()
        };
        let response = retry_if(
            move || ddb.query(&query_input),
            |err: &QueryError| matches!(err, &QueryError::ProvisionedThroughputExceeded(_)),
        ).chain_err(|| "Error fetching messages");
        let response = response.and_then(|data| {
            let mut notifs: Vec<DynamoDbNotification> = data.items.map_or_else(Vec::new, |items| {
                debug!("Got response of: {:?}", items);
                // TODO: Capture translation errors and report them as we shouldn't
                // have corrupt data
                items
                    .into_iter()
                    .inspect(|i| debug!("Item: {:?}", i))
                    .filter_map(|item| serde_dynamodb::from_hashmap(item).ok())
                    .collect()
            });
            if notifs.is_empty() {
                return Ok(Default::default());
            }

            // Load the current_timestamp from the subscription registry entry which is
            // the first DynamoDbNotification and remove it from the vec.
            let timestamp = notifs.remove(0).current_timestamp;
            // Convert any remaining DynamoDbNotifications to Notification's
            // TODO: Capture translation errors and report them as we shouldn't have corrupt data
            let messages = notifs
                .into_iter()
                .filter_map(|ddb_notif| ddb_notif.to_notif().ok())
                .collect();
            Ok(FetchMessageResponse {
                timestamp,
                messages,
            })
        });
        Box::new(response)
    }

    pub fn fetch_timestamp_messages(
        ddb: Rc<Box<DynamoDb>>,
        table_name: &str,
        uaid: &Uuid,
        timestamp: Option<u64>,
        limit: u32,
    ) -> MyFuture<FetchMessageResponse> {
        let range_key = if let Some(ts) = timestamp {
            format!("02:{}:z", ts)
        } else {
            "01;".to_string()
        };
        let attr_values = hashmap! {
            ":uaid".to_string() => val!(S => uaid.simple().to_string()),
            ":cmi".to_string() => val!(S => range_key),
        };
        let query_input = QueryInput {
            key_condition_expression: Some("uaid = :uaid AND chidmessageid > :cmi".to_string()),
            expression_attribute_values: Some(attr_values),
            table_name: table_name.to_string(),
            limit: Some(limit as i64),
            ..Default::default()
        };
        let response = retry_if(
            move || ddb.query(&query_input),
            |err: &QueryError| matches!(err, &QueryError::ProvisionedThroughputExceeded(_)),
        ).chain_err(|| "Error fetching messages");
        let response = response.and_then(|data| {
            let messages = data.items.map_or_else(Vec::new, |items| {
                debug!("Got response of: {:?}", items);
                // TODO: Capture translation errors and report them as we shouldn't have corrupt data
                items
                    .into_iter()
                    .filter_map(|item| serde_dynamodb::from_hashmap(item).ok())
                    .filter_map(|ddb_notif: DynamoDbNotification| ddb_notif.to_notif().ok())
                    .collect()
            });
            if messages.is_empty() {
                return Ok(Default::default());
            }

            let timestamp = messages.iter().filter_map(|m| m.sortkey_timestamp).max();
            Ok(FetchMessageResponse {
                timestamp,
                messages,
            })
        });
        Box::new(response)
    }

    fn drop_user(
        ddb: Rc<Box<DynamoDb>>,
        uaid: &Uuid,
        router_table_name: &str,
    ) -> MyFuture<DeleteItemOutput> {
        let delete_input = DeleteItemInput {
            table_name: router_table_name.to_string(),
            key: ddb_item! { uaid: s => uaid.simple().to_string() },
            ..Default::default()
        };
        let response = retry_if(
            move || ddb.delete_item(&delete_input),
            |err: &DeleteItemError| {
                matches!(err, &DeleteItemError::ProvisionedThroughputExceeded(_))
            },
        ).chain_err(|| "Error fetching user");
        Box::new(response)
    }

    fn get_uaid(
        ddb: Rc<Box<DynamoDb>>,
        uaid: &Uuid,
        router_table_name: &str,
    ) -> MyFuture<GetItemOutput> {
        let get_input = GetItemInput {
            table_name: router_table_name.to_string(),
            consistent_read: Some(true),
            key: ddb_item! { uaid: s => uaid.simple().to_string() },
            ..Default::default()
        };
        let response = retry_if(
            move || ddb.get_item(&get_input),
            |err: &GetItemError| matches!(err, &GetItemError::ProvisionedThroughputExceeded(_)),
        ).chain_err(|| "Error fetching user");
        Box::new(response)
    }

    fn register_user(
        ddb: Rc<Box<DynamoDb>>,
        user: &DynamoDbUser,
        router_table: &str,
    ) -> MyFuture<PutItemOutput> {
        let item = match serde_dynamodb::to_hashmap(user) {
            Ok(item) => item,
            Err(e) => return Box::new(future::err(e)).chain_err(|| "Failed to serialize item"),
        };
        let router_table = router_table.to_string();
        let attr_values = hashmap! {
            ":router_type".to_string() => val!(S => user.router_type),
            ":connected_at".to_string() => val!(N => user.connected_at),
        };
        let response: MyFuture<PutItemOutput> = {
            let ddb_response = retry_if(
                move || {
                    debug!("Registering user: {:?}", item);
                    ddb.put_item(&PutItemInput {
                        item: item.clone(),
                        table_name: router_table.clone(),
                        expression_attribute_values: Some(attr_values.clone()),
                        condition_expression: Some(
                            r#"(
                            attribute_not_exists(router_type) or
                            (router_type = :router_type)
                        ) and (
                            attribute_not_exists(node_id) or
                            (connected_at < :connected_at)
                        )"#.to_string(),
                        ),
                        return_values: Some("ALL_OLD".to_string()),
                        ..Default::default()
                    })
                },
                |err: &PutItemError| matches!(err, &PutItemError::ProvisionedThroughputExceeded(_)),
            ).chain_err(|| "Error storing user record");
            Box::new(ddb_response)
        };
        Box::new(response)
    }

    fn register_channel_id(
        ddb: Rc<Box<DynamoDb>>,
        uaid: &Uuid,
        channel_id: &Uuid,
        message_table_name: &str,
    ) -> MyFuture<UpdateItemOutput> {
        let chid = channel_id.hyphenated().to_string();
        let expiry = sec_since_epoch() + MAX_EXPIRY;
        let attr_values = hashmap! {
            ":channel_id".to_string() => val!(SS => vec![chid]),
            ":expiry".to_string() => val!(N => expiry),
        };
        let update_item = UpdateItemInput {
            key: ddb_item! {
                uaid: s => uaid.simple().to_string(),
                chidmessageid: s => " ".to_string()
            },
            update_expression: Some("ADD chids :channel_id, expiry :expiry".to_string()),
            expression_attribute_values: Some(attr_values),
            table_name: message_table_name.to_string(),
            ..Default::default()
        };
        let ddb_response = retry_if(
            move || ddb.update_item(&update_item),
            |err: &UpdateItemError| {
                matches!(err, &UpdateItemError::ProvisionedThroughputExceeded(_))
            },
        ).chain_err(|| "Error registering channel");
        Box::new(ddb_response)
    }

    fn lookup_user(
        ddb: Rc<Box<DynamoDb>>,
        uaid: &Uuid,
        connected_at: &u64,
        router_url: &str,
        router_table_name: &str,
        message_table_names: &Vec<String>,
        metrics: &StatsdClient,
    ) -> MyFuture<(HelloResponse, Option<DynamoDbUser>)> {
        let response = DynamoStorage::get_uaid(ddb.clone(), uaid, router_table_name);
        // Prep all these for the move into the static closure capture
        let cur_month = message_table_names.last().unwrap().clone();
        let uaid2 = uaid.clone();
        let ddb2 = ddb.clone();
        let router_table = router_table_name.to_string();
        let messages_tables = message_table_names.clone();
        let connected_at = connected_at.clone();
        let router_url = router_url.to_string();
        let metrics = metrics.clone();
        let response = response.and_then(move |data| -> MyFuture<_> {
            let mut hello_response: HelloResponse = Default::default();
            hello_response.message_month = cur_month.clone();
            let user = DynamoStorage::_handle_user_result(
                cur_month,
                messages_tables,
                connected_at,
                router_url,
                data,
                &mut hello_response,
            );
            match user {
                Ok(user) => Box::new(future::ok((hello_response, Some(user)))),
                Err((false, _)) => Box::new(future::ok((hello_response, None))),
                Err((true, code)) => {
                    metrics
                        .incr_with_tags("ua.expiration")
                        .with_tag("code", &code.to_string())
                        .send()
                        .ok();
                    let response = DynamoStorage::drop_user(ddb2, &uaid2, &router_table)
                        .and_then(|_| future::ok((hello_response, None)))
                        .chain_err(|| "Unable to drop user");
                    Box::new(response)
                }
            }
        });
        Box::new(response)
    }

    // Helper function for determining if a returned user record is valid for use or
    // if it should be dropped and a new one created.
    fn _handle_user_result(
        cur_month: String,
        messages_tables: Vec<String>,
        connected_at: u64,
        router_url: String,
        data: GetItemOutput,
        hello_response: &mut HelloResponse,
    ) -> StdResult<DynamoDbUser, (bool, u16)> {
        let item = data.item.ok_or((false, 104))?;
        let mut user: DynamoDbUser = serde_dynamodb::from_hashmap(item).map_err(|_| (true, 104))?;

        let user_month = user.current_month.clone();
        let month = user_month.ok_or((true, 104))?;
        if !messages_tables.contains(&cur_month) {
            return Err((true, 105));
        }
        hello_response.check_storage = true;
        hello_response.message_month = month.clone();
        hello_response.rotate_message_table = cur_month != month;
        if has_connected_this_month(&user) {
            user.last_connect = None;
        } else {
            user.last_connect = Some(generate_last_connect());
        }
        if let Some(rec_ver) = user.record_version {
            hello_response.reset_uaid = rec_ver < USER_RECORD_VERSION;
        } else {
            hello_response.reset_uaid = true;
        }
        user.node_id = Some(router_url);
        user.connected_at = connected_at;
        return Ok(user);
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
            DynamoStorage::lookup_user(
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
            let ddb_response = DynamoStorage::register_user(ddb, &user, router_table_name.as_ref())
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
        let response = DynamoStorage::register_channel_id(ddb, uaid, channel_id, message_month)
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

    pub fn drop_uaid(
        &self,
        table_name: &str,
        uaid: &Uuid,
    ) -> MyFuture<()> {
        let ddb = self.ddb.clone();
        let response = DynamoStorage::drop_user(ddb, uaid, table_name)
            .and_then(move |_| -> MyFuture<_> {
                Box::new(future::ok(()))
            })
            .chain_err(|| "Unable to drop user record");
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
            DynamoStorage::fetch_messages(ddb, table_name, uaid, 11 as u32)
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
                    DynamoStorage::fetch_timestamp_messages(
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

#[cfg(test)]
mod tests {
    use chrono::prelude::*;
    use uuid::Uuid;
    use util::us_since_epoch;
    use super::parse_sort_key;

    #[test]
    fn test_parse_sort_key_ver1() {
        let chid = Uuid::new_v4();
        let chidmessageid = format!("01:{}:mytopic", chid.hyphenated().to_string());
        let key = parse_sort_key(&chidmessageid).unwrap();
        assert_eq!(key.topic, Some("mytopic".to_string()));
        assert_eq!(key.channel_id, chid);
        assert_eq!(key.sortkey_timestamp, None);
    }

    #[test]
    fn test_parse_sort_key_ver2() {
        let chid = Uuid::new_v4();
        let sortkey_timestamp = us_since_epoch();
        let chidmessageid = format!("02:{}:{}", sortkey_timestamp, chid.hyphenated().to_string());
        let key = parse_sort_key(&chidmessageid).unwrap();
        assert_eq!(key.topic, None);
        assert_eq!(key.channel_id, chid);
        assert_eq!(key.sortkey_timestamp, Some(sortkey_timestamp));
    }

    #[test]
    fn test_parse_sort_key_bad_values() {
        for val in vec!["02j3i2o", "03:ffas:wef", "01::mytopic", "02:oops:ohnoes"] {
            let key = parse_sort_key(val);
            assert!(key.is_err());
        }
    }
}
