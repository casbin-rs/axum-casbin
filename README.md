# axum-casbin-auth
[![Crates.io](https://img.shields.io/crates/v/axum-casbin.svg)](https://crates.io/crates/axum-casbin)
[![crates.io](https://img.shields.io/crates/d/axum-casbin)](https://crates.io/crates/axum-casbin)
[![CI](https://github.com/casbin-rs/axum-casbin-auth/actions/workflows/CI.yml/badge.svg)](https://github.com/casbin-rs/axum-casbin-auth/actions/workflows/CI.yml)

## Install

Add it to `Cargo.toml`

```toml
axum = "0.5.7"
axum-casbin = "0.1.0"
tokio = { version = "1.17.0", features = [ "full" ] }
```

## Requirement

**Casbin only takes charge of permission control**, so you need to implement an `Authentication Middleware` to identify user.

You should put `axum_casbin_auth::CasbinVals` which contains `subject`(username) and `domain`(optional) into [Extension](https://docs.rs/http/0.2.8/http/struct.Extensions.html).

For example:
```rust
use axum::{response::Response, BoxError};
use futures::future::BoxFuture;

use bytes::Bytes;
use http::{self, Request};
use http_body::Body as HttpBody;
use std::{
    boxed::Box,
    convert::Infallible,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use axum_casbin_auth::CasbinVals;

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
```

## Example
```rust
use axum::{routing::get, Router};
use axum_casbin_auth::{CasbinAxumLayer};
use axum_casbin_auth::casbin::function_map::key_match2;
use axum_casbin_auth::casbin::{CoreApi, DefaultModel, FileAdapter, Result};

// Handler that immediately returns an empty `200 OK` response.
async fn handler() {}

#[tokio::main]
async fn main() -> Result<()> {
    let m = DefaultModel::from_file("examples/rbac_with_pattern_model.conf")
        .await
        .unwrap();

    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");

    let casbin_middleware = CasbinAxumLayer::new(m, a).await.unwrap();

    casbin_middleware
        .write()
        .await
        .get_role_manager()
        .write()
        .matching_fn(Some(key_match2), None);

    let app = Router::new()
        .route("/pen/1", get(handler))
        .route("/pen/2", get(handler))
        .route("/book/:id", get(handler))
        .layer(casbin_middleware)
        .layer(FakeAuthLayer);

    axum::Server::bind(&"127.0.0.1:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await;
    
        Ok(())
}
```

## License

This project is licensed under

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
