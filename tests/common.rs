use axum::extract::Request;
use std::task::{Context, Poll};
use tower::{Layer, Service};

pub use axum::{http::StatusCode, routing::get, Router};
pub use axum_casbin::{CasbinAxumLayer, CasbinVals};
pub use axum_test::TestServer;
pub use casbin::{CoreApi, DefaultModel, FileAdapter};

pub async fn handler() {}

#[derive(Clone)]
pub struct TestAuthLayer(pub CasbinVals);

impl<S> Layer<S> for TestAuthLayer {
    type Service = TestAuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TestAuthMiddleware(inner, self.0.clone())
    }
}

#[derive(Clone)]
pub struct TestAuthMiddleware<S>(S, CasbinVals);

impl<S> Service<Request> for TestAuthMiddleware<S>
where
    S: Service<Request>,
{
    type Error = S::Error;
    type Future = S::Future;
    type Response = S::Response;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }
    fn call(&mut self, mut req: Request) -> Self::Future {
        req.extensions_mut().insert(self.1.clone());
        self.0.call(req)
    }
}
