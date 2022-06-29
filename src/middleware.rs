use axum::{body::Body, http::Request, http::StatusCode, response::Response};
use casbin::prelude::{TryIntoAdapter, TryIntoModel};
use casbin::{CachedEnforcer, CoreApi, Result as CasbinResult};
use futures::future::BoxFuture;
use std::error::Error;
use std::fmt;
use std::ops::{Deref, DerefMut};
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

#[derive(Debug)]
struct Unauthorized;

impl Error for Unauthorized {}

impl fmt::Display for Unauthorized {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", StatusCode::UNAUTHORIZED)
    }
}

#[derive(Debug)]
struct BadGateway;

impl Error for BadGateway {}

impl fmt::Display for BadGateway {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", StatusCode::BAD_GATEWAY)
    }
}
#[derive(Debug)]
struct Forbidden;

impl Error for Forbidden {}

impl fmt::Display for Forbidden {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", StatusCode::FORBIDDEN)
    }
}
#[derive(Clone)]
pub struct CasbinAxumMiddleware<S> {
    inner: S,
    enforcer: Arc<RwLock<CachedEnforcer>>,
}

impl<S> Service<Request<Body>> for CasbinAxumMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn Error + Send + Sync>> + 'static,
{
    type Response = S::Response;
    type Error = Box<dyn Error + Send + Sync>;
    // `BoxFuture` is a type alias for `Pin<Box<dyn Future + Send + 'a>>`
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let cloned_enforcer = self.enforcer.clone();
        let clone = self.inner.clone();
        let mut srv = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let path = req.uri().path().to_string();
            let action = req.method().as_str().to_string();
            let option_vals = req.extensions().get::<CasbinVals>().map(|x| x.to_owned());
            let vals = match option_vals {
                Some(value) => value,
                None => {
                    return Err(Box::new(Unauthorized) as Box<dyn Error + Send + Sync>);
                }
            };

            let subject = vals.subject.clone();

            if !vals.subject.is_empty() {
                if let Some(domain) = vals.domain {
                    let mut lock = cloned_enforcer.write().await;
                    match lock.enforce_mut(vec![subject, domain, path, action]) {
                        Ok(true) => {
                            drop(lock);
                            return srv.call(req).await.map_err(|err| err.into());
                        }
                        Ok(false) => {
                            drop(lock);
                            return Err(Box::new(Forbidden) as Box<dyn Error + Send + Sync>);
                        }
                        Err(_) => {
                            drop(lock);
                            return Err(Box::new(BadGateway) as Box<dyn Error + Send + Sync>);
                        }
                    }
                } else {
                    let mut lock = cloned_enforcer.write().await;
                    match lock.enforce_mut(vec![subject, path, action]) {
                        Ok(true) => {
                            drop(lock);
                            return srv.call(req).await.map_err(|err| err.into());
                        }
                        Ok(false) => {
                            drop(lock);
                            return Err(Box::new(Forbidden) as Box<dyn Error + Send + Sync>);
                        }
                        Err(_) => {
                            drop(lock);
                            return Err(Box::new(BadGateway) as Box<dyn Error + Send + Sync>);
                        }
                    }
                }
            } else {
                return Err(Box::new(Unauthorized) as Box<dyn Error + Send + Sync>);
            }
        })
    }
}
