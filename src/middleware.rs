
use axum::{body::Body, http::Request, response::Response};
use std::cell::RefCell;
use std::rc::Rc;

use casbin::prelude::{TryIntoAdapter, TryIntoModel};
use casbin::{CachedEnforcer, CoreApi, Result as CasbinResult};
use futures::future::{BoxFuture};
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

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
pub struct CasbinAxumService {
    enforcer: Arc<RwLock<CachedEnforcer>>,
}

impl CasbinAxumService {
    pub async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> CasbinResult<Self> {
        let enforcer: CachedEnforcer = CachedEnforcer::new(m, a).await?;
        Ok(CasbinAxumService {
            enforcer: Arc::new(RwLock::new(enforcer)),
        })
    }

    pub fn get_enforcer(&mut self) -> Arc<RwLock<CachedEnforcer>> {
        self.enforcer.clone()
    }

    pub fn set_enforcer(e: Arc<RwLock<CachedEnforcer>>) -> CasbinAxumService {
        CasbinAxumService { enforcer: e }
    }
}
// refer some more documentation from here, since it is specific to middleware
impl<S> Layer<S> for CasbinAxumService {
    type Service = CasbinAxumMiddleware<S>;

    // This function may be required to update or integrate with casbin
    fn layer(&self, service: S) -> Self::Service {
        // Check whether we need to use something for output as Service
        CasbinAxumMiddleware {
            enforcer: self.enforcer.clone(),
            service: Rc::new(RefCell::new(service)),
        }
    }
}

#[derive(Clone)]
pub struct CasbinAxumMiddleware<S> {
    service: Rc<RefCell<S>>,
    enforcer: Arc<RwLock<CachedEnforcer>>,
}

impl<S> Service<Request<Body>> for CasbinAxumMiddleware<S>
where
    // Here need to decide on the request/service, it is making the issue
    S: Service<Request<Body>, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    // `BoxFuture` is a type alias for `Pin<Box<dyn Future + Send + 'a>>`
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    // poll and call methods can be understood by reading the service in tower_service
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(self.service.poll_ready(cx)))
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let future = self.service.call(request);
        Box::pin(async move {
            let response: Response = future.await?;
            Ok(response)
        })
    }
}
