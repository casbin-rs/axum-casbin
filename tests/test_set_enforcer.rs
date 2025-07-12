use common::*;
mod common;

use casbin::function_map::key_match2;
use casbin::CachedEnforcer;
use std::sync::Arc;

#[cfg(feature = "runtime-tokio")]
use tokio::sync::RwLock;

#[cfg(feature = "runtime-async-std")]
use async_std::sync::RwLock;

#[cfg_attr(feature = "runtime-tokio", tokio::test)]
#[cfg_attr(feature = "runtime-async-std", async_std::test)]
async fn test_set_enforcer() {
    let m = DefaultModel::from_file("examples/rbac_with_pattern_model.conf")
        .await
        .unwrap();
    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");

    let enforcer = Arc::new(RwLock::new(CachedEnforcer::new(m, a).await.unwrap()));

    let casbin_middleware = CasbinAxumLayer::set_enforcer(enforcer);

    casbin_middleware
        .write()
        .await
        .get_role_manager()
        .write()
        .matching_fn(Some(key_match2), None);

    let app = Router::new()
        .route("/pen/1", get(handler))
        .route("/pen/2", get(handler))
        .route("/book/{id}", get(handler))
        .layer(casbin_middleware)
        .layer(TestAuthLayer(CasbinVals {
            subject: String::from("alice"),
            domain: None,
        }));

    let client = TestServer::new(app).unwrap();

    let resp_pen_1 = client.get("/pen/1").await;
    assert_eq!(resp_pen_1.status_code(), StatusCode::OK);

    let resp_book = client.get("/book/2").await;
    assert_eq!(resp_book.status_code(), StatusCode::OK);

    let resp_pen_2 = client.get("/pen/2").await;
    assert_eq!(resp_pen_2.status_code(), StatusCode::FORBIDDEN);
}
