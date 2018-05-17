use std::collections::HashSet;
use std::rc::Rc;
use std::result::Result as StdResult;
use uuid::Uuid;

use cadence::{Counted, StatsdClient};
use chrono::Utc;
use futures::{future, Future};
use futures_backoff::retry_if;
use rusoto_dynamodb::{
    AttributeValue, DeleteItemError, DeleteItemInput, DeleteItemOutput, DynamoDb, GetItemError,
    GetItemInput, GetItemOutput, PutItemError, PutItemInput, PutItemOutput, QueryError, QueryInput,
    UpdateItemError, UpdateItemInput, UpdateItemOutput,
};
use serde_dynamodb;

use errors::*;
use protocol::Notification;
use util::timing::sec_since_epoch;
use super::models::{DynamoDbNotification, DynamoDbUser};
use super::util::generate_last_connect;
use super::{HelloResponse, MAX_EXPIRY, USER_RECORD_VERSION};

#[derive(Default)]
pub struct FetchMessageResponse {
    pub timestamp: Option<u64>,
    pub messages: Vec<Notification>,
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

pub fn drop_user(
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
        |err: &DeleteItemError| matches!(err, &DeleteItemError::ProvisionedThroughputExceeded(_)),
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

pub fn register_user(
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

pub fn update_user_message_month(
    ddb: Rc<Box<DynamoDb>>,
    uaid: &Uuid,
    router_table_name: &str,
    message_month: &str,
) -> MyFuture<()> {
    let attr_values = hashmap! {
        ":curmonth".to_string() => val!(S => message_month.to_string()),
        ":lastconnect".to_string() => val!(N => generate_last_connect().to_string()),
    };
    let update_item = UpdateItemInput {
        key: ddb_item! { uaid: s => uaid.simple().to_string() },
        update_expression: Some(
            "SET current_month=:curmonth, last_connect=:lastconnect".to_string(),
        ),
        expression_attribute_values: Some(attr_values),
        table_name: router_table_name.to_string(),
        ..Default::default()
    };
    let ddb_response = retry_if(
        move || {
            ddb.update_item(&update_item)
                .and_then(|_| Box::new(future::ok(())))
        },
        |err: &UpdateItemError| matches!(err, &UpdateItemError::ProvisionedThroughputExceeded(_)),
    ).chain_err(|| "Error updating user message month");
    Box::new(ddb_response)
}

pub fn all_channels(
    ddb: Rc<Box<DynamoDb>>,
    uaid: &Uuid,
    message_table_name: &str,
) -> MyFuture<HashSet<String>> {
    let get_input = GetItemInput {
        table_name: message_table_name.to_string(),
        consistent_read: Some(true),
        key: ddb_item! {
            uaid: s => uaid.simple().to_string(),
            chidmessageid: s => " ".to_string()
        },
        ..Default::default()
    };
    let response = retry_if(
        move || ddb.get_item(&get_input),
        |err: &GetItemError| matches!(err, &GetItemError::ProvisionedThroughputExceeded(_)),
    ).and_then(|get_item_output| {
        let result = get_item_output.item.and_then(|item| {
            let record: Option<DynamoDbNotification> = serde_dynamodb::from_hashmap(item).ok();
            record
        });
        let channels = if let Some(record) = result {
            record.chids.unwrap_or_else(|| HashSet::new())
        } else {
            HashSet::new()
        };
        Box::new(future::ok(channels))
    })
        .or_else(|_err| Box::new(future::ok(HashSet::new())));
    Box::new(response)
}

pub fn save_channels(
    ddb: Rc<Box<DynamoDb>>,
    uaid: &Uuid,
    channels: HashSet<String>,
    message_table_name: &str,
) -> MyFuture<()> {
    let chids: Vec<String> = channels.into_iter().collect();
    let expiry = sec_since_epoch() + 2 * MAX_EXPIRY;
    let attr_values = hashmap! {
        ":chids".to_string() => val!(SS => chids),
        ":expiry".to_string() => val!(N => expiry),
    };
    let update_item = UpdateItemInput {
        key: ddb_item! {
            uaid: s => uaid.simple().to_string(),
            chidmessageid: s => " ".to_string()
        },
        update_expression: Some("ADD chids :chids SET expiry=:expiry".to_string()),
        expression_attribute_values: Some(attr_values),
        table_name: message_table_name.to_string(),
        ..Default::default()
    };
    let ddb_response = retry_if(
        move || {
            ddb.update_item(&update_item)
                .and_then(|_| Box::new(future::ok(())))
        },
        |err: &UpdateItemError| matches!(err, &UpdateItemError::ProvisionedThroughputExceeded(_)),
    ).chain_err(|| "Error saving channels");
    Box::new(ddb_response)
}

pub fn unregister_channel_id(
    ddb: Rc<Box<DynamoDb>>,
    uaid: &Uuid,
    channel_id: &Uuid,
    message_table_name: &str,
) -> MyFuture<UpdateItemOutput> {
    let chid = channel_id.hyphenated().to_string();
    let attr_values = hashmap! {
        ":channel_id".to_string() => val!(SS => vec![chid]),
    };
    let update_item = UpdateItemInput {
        key: ddb_item! {
            uaid: s => uaid.simple().to_string(),
            chidmessageid: s => " ".to_string()
        },
        update_expression: Some("DELETE chids :channel_id".to_string()),
        expression_attribute_values: Some(attr_values),
        table_name: message_table_name.to_string(),
        ..Default::default()
    };
    let ddb_response = retry_if(
        move || ddb.update_item(&update_item),
        |err: &UpdateItemError| matches!(err, &UpdateItemError::ProvisionedThroughputExceeded(_)),
    ).chain_err(|| "Error unregistering channel");
    Box::new(ddb_response)
}

pub fn lookup_user(
    ddb: Rc<Box<DynamoDb>>,
    uaid: &Uuid,
    connected_at: &u64,
    router_url: &str,
    router_table_name: &str,
    message_table_names: &Vec<String>,
    metrics: &StatsdClient,
) -> MyFuture<(HelloResponse, Option<DynamoDbUser>)> {
    let response = get_uaid(ddb.clone(), uaid, router_table_name);
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
        let user = _handle_user_result(
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
                let response = drop_user(ddb2, &uaid2, &router_table)
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
