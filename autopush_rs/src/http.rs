use std::str;
use std::rc::Rc;

use futures::future::err;
use futures::{Stream, Future};
use hyper::Method;
use hyper;
use time;
use tokio_service::Service;
use uuid::Uuid;

use server::Server;

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
        let channel_id = match req.uri().path()[1..].parse::<Uuid>() {
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
            let version = if body.len() == 0 {
                time::now_utc().to_timespec().sec as u64
            } else {
                if !form_encoded {
                    println!("bad content type");
                    return Err(hyper::Error::Incomplete)
                }
                let header = b"version=";
                if !body.starts_with(header) {
                    println!("bad body");
                    return Err(hyper::Error::Incomplete)
                }
                let vers = str::from_utf8(&body[header.len()..]).ok()
                    .and_then(|s| s.parse::<u64>().ok());
                match vers {
                    Some(vers) => vers,
                    None => {
                        println!("failed to parse version");
                        return Err(hyper::Error::Incomplete)
                    }
                }
            };

            srv.notify_client(&channel_id, version);

            Ok(hyper::Response::new())
        }))
    }
}
