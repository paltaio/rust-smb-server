//! The HTTP client against the gateway.

use std::time::Duration;

use http::{Request, StatusCode};

use super::gateway::gateway;
use crate::s3::payload::Payload;
use crate::s3::transport::{Activity, RequestBody, client};

#[tokio::test]
async fn gets_the_health_path_over_plain_http() {
    let gateway = tokio::task::spawn_blocking(gateway).await.unwrap();
    let client = client().unwrap();
    let request = Request::get(format!("http://{}/health", gateway.addr))
        .body(RequestBody::new(&Payload::empty(), Activity::new()))
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(10), client.request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
