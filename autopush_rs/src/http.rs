//! Dummy module that's very likely to get entirely removed
//!
//! For now just a small HTTP server used to send notifications to our dummy
//! clients.

use std::str;
use std::rc::Rc;

use errors::*;
use futures::future::err;
use futures::{Stream, Future};
use hyper::Method;
use hyper;
use serde_json;
use time;
use tokio_service::Service;
use uuid::Uuid;

use server::Server;
use protocol::Notification;

pub struct Push(pub Rc<Server>);

impl Service for Push {
    type Request = hyper::Request;
    type Response = hyper::Response;
    type Error = hyper::Error;
    type Future = Box<Future<Item = hyper::Response, Error = hyper::Error>>;

    fn call(&self, req: hyper::Request) -> Self::Future {
        use hyper::header::ContentType;

        if *req.method() != Method::Put && *req.method() != Method::Post {
            println!("not a PUT: {}", req.method());
            return Box::new(err(hyper::Error::Method))
        }
        if req.uri().path().len() == 0 {
            println!("empty uri path");
            return Box::new(err(hyper::Error::Incomplete))
        }
        let uaid = match req.uri().path()[1..].parse::<Uuid>() {
            Ok(id) => id,
            Err(_) => {
                println!("uri not uuid: {}", req.uri().path());
                return Box::new(err(hyper::Error::Status))
            }
        };
        let form_encoded = match req.headers().get::<ContentType>() {
            Some(header) => **header == "application/x-www-form-urlencoded",
            None => false,
        };

        let body = req.body().concat2();
        let srv = self.0.clone();
        Box::new(body.and_then(move |body| {
            let s = String::from_utf8(body.to_vec()).unwrap();
            if let Ok(msg) = serde_json::from_str(&s) {
                match srv.notify_client(uaid, msg) {
                    Ok(_) => return Ok(hyper::Response::new()
                        .with_status(hyper::StatusCode::Ok)
                    ),
                    _ => return Ok(hyper::Response::new()
                        .with_status(hyper::StatusCode::BadRequest)
                        .with_body("Unable to decode body payload")
                    )
                }
            }
            Ok(hyper::Response::new()
                .with_status(hyper::StatusCode::NotFound)
            )
        }))
    }
}
