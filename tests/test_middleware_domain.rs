use common::*;
mod common;

#[cfg_attr(feature = "runtime-tokio", tokio::test)]
#[cfg_attr(feature = "runtime-async-std", async_std::test)]
async fn test_middleware_domain() {
    let m = DefaultModel::from_file("examples/rbac_with_domains_model.conf")
        .await
        .unwrap();
    let a = FileAdapter::new("examples/rbac_with_domains_policy.csv");

    let casbin_middleware = CasbinAxumLayer::new(m, a).await.unwrap();

    let app = Router::new()
        .route("/pen/1", get(handler))
        .route("/book/1", get(handler))
        .layer(casbin_middleware)
        .layer(TestAuthLayer(CasbinVals {
            subject: "alice".into(),
            domain: Some("domain1".into()),
        }));

    let client = TestServer::new(app).unwrap();

    let resp_pen = client.get("/pen/1").await;
    assert_eq!(resp_pen.status_code(), StatusCode::OK);

    let resp_book = client.get("/book/1").await;
    assert_eq!(resp_book.status_code(), StatusCode::FORBIDDEN);
}
