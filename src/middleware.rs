use axum::{body, response::Response, BoxError};
use bytes::Bytes;
use casbin::prelude::{TryIntoAdapter, TryIntoModel};
use casbin::{CachedEnforcer, CoreApi, Result as CasbinResult};
use futures::future::BoxFuture;
use http::{Request, StatusCode};
use http_body::Body as HttpBody;
use http_body_util::Full;
use std::{
    convert::Infallible,
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

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CasbinAxumMiddleware<S>
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
    type Response = Response;
    type Error = Infallible;
    // `BoxFuture` is a type alias for `Pin<Box<dyn Future + Send + 'a>>`
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let cloned_enforcer = self.enforcer.clone();
        let not_ready_inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, not_ready_inner);

        Box::pin(async move {
            let path = req.uri().path().to_string();
            let action = req.method().as_str().to_string();
            let option_vals = req.extensions().get::<CasbinVals>().map(|x| x.to_owned());
            let vals = match option_vals {
                Some(value) => value,
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(body::Body::new(Full::from("401 Unauthorized")))
                        .unwrap());
                }
            };

            let subject = vals.subject.clone();

            if !vals.subject.is_empty() {
                if let Some(domain) = vals.domain {
                    let mut lock = cloned_enforcer.write().await;
                    match lock.enforce_mut(vec![subject, domain, path, action]) {
                        Ok(true) => {
                            drop(lock);
                            Ok(inner.call(req).await?.map(body::Body::new))
                        }
                        Ok(false) => {
                            drop(lock);
                            Ok(Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(body::Body::new(Full::from("403 Forbidden")))
                                .unwrap())
                        }
                        Err(_) => {
                            drop(lock);
                            Ok(Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .body(body::Body::new(Full::from("502 Bad Gateway")))
                                .unwrap())
                        }
                    }
                } else {
                    let mut lock = cloned_enforcer.write().await;
                    match lock.enforce_mut(vec![subject, path, action]) {
                        Ok(true) => {
                            drop(lock);
                            Ok(inner.call(req).await?.map(body::Body::new))
                        }
                        Ok(false) => {
                            drop(lock);
                            Ok(Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(body::Body::new(Full::from("403 Forbidden")))
                                .unwrap())
                        }
                        Err(_) => {
                            drop(lock);
                            Ok(Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .body(body::Body::new(Full::from("502 Bad Gateway")))
                                .unwrap())
                        }
                    }
                }
            } else {
                Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(body::Body::new(Full::from("401 Unauthorized")))
                    .unwrap())
            }
        })
    }
}
