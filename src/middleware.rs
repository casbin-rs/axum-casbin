use axum::{
    response::Response,
    body::Body,
    http::Request,
};

use futures::future::BoxFuture;
use tower::{Service, Layer};
use std::{task::{Context, Poll}, sync::Arc};
use casbin::prelude::{TryIntoAdapter, TryIntoModel};
use casbin::{CachedEnforcer, CoreApi, Result as CasbinResult};

#[cfg(feature = "runtime-tokio")]
use tokio::sync::RwLock;

#[cfg(feature = "runtime-async-std")]
use async_std::sync::RwLock;

#[derive(Clone)]
pub struct CasbinVals {
    pub subject: String,
    pub domain: Option<String>,
}
#[derive(Clone)]
struct CasbinService {
    enforcer: Arc<RwLock<CachedEnforcer>>,
}

impl CasbinService {
    pub async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> CasbinResult<Self> {
        let enforcer: CachedEnforcer = CachedEnforcer::new(m, a).await?;
        Ok(CasbinService {
            enforcer: Arc::new(RwLock::new(enforcer)),
        })
    }

    pub fn get_enforcer(&mut self) -> Arc<RwLock<CachedEnforcer>> {
        self.enforcer.clone()
    }

    pub fn set_enforcer(e: Arc<RwLock<CachedEnforcer>>) -> CasbinService {
        CasbinService { enforcer: e }
    }
}
// refer some more documentation from here, since it is specific to middleware
impl<S> Layer<S> for CasbinService {
    type Service = CasbinAxumMiddleware<S>;

    // This function may be required to update or integrate with casbin
    fn layer(&self, inner: S) -> Self::Service {
        CasbinAxumMiddleware { inner }
    }
}

#[derive(Clone)]
struct CasbinAxumMiddleware<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for CasbinAxumMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    // `BoxFuture` is a type alias for `Pin<Box<dyn Future + Send + 'a>>`
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let future = self.inner.call(request);
        Box::pin(async move {
            let response: Response = future.await?;
            Ok(response)
        })
    }
}