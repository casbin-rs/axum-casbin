use axum::{response::Response, routing::get, BoxError, Router};
use axum_casbin::{CasbinAxumLayer, CasbinVals};
use axum_test::TestServer;
use bytes::Bytes;
use casbin::function_map::key_match2;
use casbin::{CachedEnforcer, CoreApi, DefaultModel, FileAdapter};
use futures::future::BoxFuture;
use http::{Request, StatusCode};
use http_body::Body as HttpBody;
use std::{
    convert::Infallible,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

#[cfg(feature = "runtime-tokio")]
use tokio::sync::RwLock;

#[cfg(feature = "runtime-async-std")]
use async_std::sync::RwLock;

#[derive(Clone)]
struct FakeAuthLayer;

impl<S> Layer<S> for FakeAuthLayer {
    type Service = FakeAuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        FakeAuthMiddleware { inner }
    }
}

#[derive(Clone)]
struct FakeAuthMiddleware<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for FakeAuthMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    Infallible: From<<S as Service<Request<ReqBody>>>::Error>,
    ResBody: HttpBody<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = S::Error;
    // `BoxFuture` is a type alias for `Pin<Box<dyn Future + Send + 'a>>`
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let not_ready_inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, not_ready_inner);

        Box::pin(async move {
            let vals = CasbinVals {
                subject: String::from("alice"),
                domain: None,
            };
            req.extensions_mut().insert(vals);
            inner.call(req).await
        })
    }
}

// Handler that immediately returns an empty `200 OK` response.
async fn handler() {}

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
        .layer(FakeAuthLayer);

    let client = TestServer::new(app).unwrap();

    let resp_pen_1 = client.get("/pen/1").await;
    assert_eq!(resp_pen_1.status_code(), StatusCode::OK);

    let resp_book = client.get("/book/2").await;
    assert_eq!(resp_book.status_code(), StatusCode::OK);

    let resp_pen_2 = client.get("/pen/2").await;
    assert_eq!(resp_pen_2.status_code(), StatusCode::FORBIDDEN);
}
