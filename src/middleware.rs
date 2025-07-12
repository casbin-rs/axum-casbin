use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use casbin::prelude::{TryIntoAdapter, TryIntoModel};
use casbin::{CachedEnforcer, CoreApi, Result as CasbinResult};
use std::future::Future;
use std::pin::Pin;
use std::{
    ops::{Deref, DerefMut},
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
pub struct CasbinAxumLayer {
    enforcer: Arc<RwLock<CachedEnforcer>>,
}

impl CasbinAxumLayer {
    pub async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> CasbinResult<Self> {
        let enforcer: CachedEnforcer = CachedEnforcer::new(m, a).await?;
        Ok(CasbinAxumLayer {
            enforcer: Arc::new(RwLock::new(enforcer)),
        })
    }

    pub fn get_enforcer(&mut self) -> Arc<RwLock<CachedEnforcer>> {
        self.enforcer.clone()
    }

    pub fn set_enforcer(e: Arc<RwLock<CachedEnforcer>>) -> CasbinAxumLayer {
        CasbinAxumLayer { enforcer: e }
    }
}

impl<S> Layer<S> for CasbinAxumLayer {
    type Service = CasbinAxumMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CasbinAxumMiddleware {
            enforcer: self.enforcer.clone(),
            inner,
        }
    }
}

impl Deref for CasbinAxumLayer {
    type Target = Arc<RwLock<CachedEnforcer>>;

    fn deref(&self) -> &Self::Target {
        &self.enforcer
    }
}

impl DerefMut for CasbinAxumLayer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.enforcer
    }
}

#[derive(Clone)]
pub struct CasbinAxumMiddleware<S> {
    inner: S,
    enforcer: Arc<RwLock<CachedEnforcer>>,
}

impl<S> Service<Request> for CasbinAxumMiddleware<S>
where
    S: Service<Request, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let cloned_enforcer = self.enforcer.clone();
        let path = req.uri().path().to_string();
        let action = req.method().as_str().to_string();
        let option_vals = req.extensions().get::<CasbinVals>().cloned();
        let future = self.inner.call(req);

        Box::pin(async move {
            fn ok<E>(s: StatusCode) -> Result<Response, E> {
                Ok(s.into_response())
            }

            let vals = match option_vals {
                Some(value) => value,
                None => {
                    return ok(StatusCode::UNAUTHORIZED);
                }
            };

            let subject = vals.subject;

            if subject.is_empty() {
                return ok(StatusCode::UNAUTHORIZED);
            }

            let args = if let Some(domain) = vals.domain {
                vec![subject, domain, path, action]
            } else {
                vec![subject, path, action]
            };

            let result = {
                let mut guard = cloned_enforcer.write().await;
                guard.enforce_mut(args)
            };

            match result {
                Ok(true) => Ok(future.await?),
                Ok(false) => ok(StatusCode::FORBIDDEN),
                Err(_) => ok(StatusCode::BAD_GATEWAY),
            }
        })
    }
}
