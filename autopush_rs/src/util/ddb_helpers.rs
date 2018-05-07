/// DynamoDB Client helpers
use std::env;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use uuid::Uuid;

use futures::Future;
use futures::future;
use futures_backoff::retry_if;
use regex::RegexSet;
use rusoto_core::Region;
use rusoto_core::reactor::RequestDispatcher;
use rusoto_credential::StaticProvider;
use rusoto_dynamodb::{AttributeValue, DynamoDb, DynamoDbClient, QueryError, QueryInput,
                      UpdateItemError, UpdateItemInput, UpdateItemOutput};
use serde_dynamodb;
use time;

use protocol::Notification;
use errors::*;

const MAX_EXPIRY: u64 = 2592000;

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

#[allow(unused_macros)]
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

/// Direct representation of a DynamoDB Notification as we store it in the database
/// Most attributes are optional
#[derive(Default, Deserialize, PartialEq, Debug, Clone)]
pub struct NotificationHeaders {
    crypto_key: Option<String>,
    encryption: Option<String>,
    encryption_key: Option<String>,
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

#[derive(Default, Deserialize, PartialEq, Debug, Clone)]
pub struct DynamoDbNotification {
    // DynamoDB <Hash key>
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
    current_timestamp: Option<u64>,
    // Magic entry stored in the first Message record that indicates the valid
    // channel id's
    chids: Option<HashSet<String>>,
    // Time in seconds from epoch
    timestamp: Option<u32>,
    // DynamoDB expiration timestamp per
    //    https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html
    expiry: u32,
    // TTL value provided by application server for the message
    ttl: Option<u32>,
    data: Option<String>,
    headers: Option<NotificationHeaders>,
    // This is the acknowledgement-id used for clients to ack that they have received the
    // message. Some Python code refers to this as a message_id. Endpoints generate this
    // value before sending it to storage or a connection node.
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

pub struct CheckStorageResponse {
    pub include_topic: bool,
    pub messages: Vec<Notification>,
    pub timestamp: Option<u64>,
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
        let uaid = uaid.simple().to_string();
        let table_name = table_name.to_string();
        let timestamp = timestamp.to_string();
        let ddb_response = retry_if(
            move || {
                let expiry = (time::get_time().sec as u64) + MAX_EXPIRY;
                let mut attr_values = HashMap::new();
                attr_values.insert(
                    ":timestamp".to_string(),
                    AttributeValue {
                        n: Some(timestamp.clone()),
                        ..Default::default()
                    },
                );
                attr_values.insert(
                    ":expiry".to_string(),
                    AttributeValue {
                        n: Some(expiry.to_string()),
                        ..Default::default()
                    },
                );
                ddb.update_item(&UpdateItemInput {
                    key: ddb_item! {
                        uaid: s => uaid.clone(),
                        chidmessageid: s => " ".to_string()
                    },
                    update_expression: Some(
                        "SET current_timestamp=:timestamp, expiry=:expiry".to_string(),
                    ),
                    expression_attribute_values: Some(attr_values),
                    table_name: table_name.clone(),
                    ..Default::default()
                })
            },
            |err: &UpdateItemError| {
                matches!(err, &UpdateItemError::ProvisionedThroughputExceeded(_))
            },
        ).map_err(|_| "Error incrementing storage".into());
        Box::new(ddb_response)
    }

    pub fn fetch_messages(
        ddb: Rc<Box<DynamoDb>>,
        table_name: &str,
        uaid: &Uuid,
        limit: u32,
    ) -> MyFuture<FetchMessageResponse> {
        let uaid = uaid.simple().to_string();
        let table_name = table_name.to_string();
        let response = retry_if(
            move || {
                let mut attr_values = HashMap::new();
                attr_values.insert(
                    ":uaid".to_string(),
                    AttributeValue {
                        s: Some(uaid.clone()),
                        ..Default::default()
                    },
                );
                attr_values.insert(
                    ":cmi".to_string(),
                    AttributeValue {
                        s: Some("02".to_string()),
                        ..Default::default()
                    },
                );
                ddb.query(&QueryInput {
                    key_condition_expression: Some(
                        "uaid = :uaid AND chidmessageid < :cmi".to_string(),
                    ),
                    expression_attribute_values: Some(attr_values),
                    table_name: table_name.clone(),
                    limit: Some(limit as i64),
                    ..Default::default()
                })
            },
            |err: &QueryError| matches!(err, &QueryError::ProvisionedThroughputExceeded(_)),
        ).map_err(|_| "Error fetching messages".into());
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
        let uaid = uaid.simple().to_string();
        let table_name = table_name.to_string();
        let timestamp = timestamp.clone();
        let response = retry_if(
            move || {
                let mut attr_values = HashMap::new();
                attr_values.insert(
                    ":uaid".to_string(),
                    AttributeValue {
                        s: Some(uaid.clone()),
                        ..Default::default()
                    },
                );
                let range_key = if let Some(ts) = timestamp {
                    format!("02:{}:z", ts)
                } else {
                    "01;".to_string()
                };
                attr_values.insert(
                    ":cmi".to_string(),
                    AttributeValue {
                        s: Some(range_key),
                        ..Default::default()
                    },
                );
                ddb.query(&QueryInput {
                    key_condition_expression: Some(
                        "uaid = :uaid AND chidmessageid > :cmi".to_string(),
                    ),
                    expression_attribute_values: Some(attr_values),
                    table_name: table_name.clone(),
                    limit: Some(limit as i64),
                    ..Default::default()
                })
            },
            |err: &QueryError| matches!(err, &QueryError::ProvisionedThroughputExceeded(_)),
        ).map_err(|_| "Error fetching messages".into());
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
