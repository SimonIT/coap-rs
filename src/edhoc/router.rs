//! Serves the EDHOC Responder role through the router: mount `edhoc_route()` at
//! `EDHOC_WELL_KNOWN_PATH` on a `Router<EdhocRouterState>` (or a router whose own state
//! implements `FromRef<_>` for `EdhocRouterState`).

use std::sync::Arc;

use super::{process_edhoc_message, EdhocCredentialStore, EdhocResponderStore, EdhocSessionHook};
use crate::router::{
    extract::{FromRequest, State},
    method_routing::{post, MethodRouter},
    request::Request,
    response::{IntoResponse, Response, StatusCode},
};

/// Application state required to serve EDHOC over the router.
///
/// If your router's own state is not `EdhocRouterState` itself, implement
/// `FromRef<YourState>` for `EdhocRouterState` so `State` can extract it (see
/// `crate::router::extract::FromRef`).
#[derive(Clone)]
pub struct EdhocRouterState {
    /// Storage for sessions awaiting `message_3`.
    pub store: Arc<EdhocResponderStore>,
    /// Trust store used to authenticate Initiators.
    pub credentials: Arc<dyn EdhocCredentialStore>,
    /// Optional hook notified with the derived OSCORE key material once a session completes.
    pub hook: Option<Arc<dyn EdhocSessionHook>>,
}

/// Extractor that yields the raw request payload. EDHOC messages are not themselves CBOR- or
/// JSON-encoded as a whole (only individual fields within them are), so the existing `Cbor`/
/// `Json` extractors don't apply here.
pub struct RawBody(Vec<u8>);

impl<S: Sync> FromRequest<S> for RawBody {
    type Rejection = std::convert::Infallible;

    async fn from_request(req: &Request, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(RawBody(req.payload()))
    }
}

/// Extractor that yields the requesting peer's socket address.
pub struct PeerAddr(std::net::SocketAddr);

impl<S: Sync> FromRequest<S> for PeerAddr {
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: &Request, _state: &S) -> Result<Self, Self::Rejection> {
        req.req
            .source
            .map(PeerAddr)
            .ok_or((StatusCode::InternalServerError, "no peer address"))
    }
}

impl IntoResponse for super::EdhocError {
    fn into_response(self) -> Response {
        Response::new()
            .set_status_code(StatusCode::BadRequest)
            .set_payload(self.to_string().into_bytes())
    }
}

/// Handler for `/.well-known/edhoc`, serving both legs of an EDHOC exchange (see
/// `process_edhoc_message`).
pub async fn edhoc_route_handler(
    State(state): State<EdhocRouterState>,
    PeerAddr(peer): PeerAddr,
    RawBody(payload): RawBody,
) -> Response {
    match process_edhoc_message(
        &state.store,
        state.credentials.as_ref(),
        state.hook.as_deref(),
        peer,
        &payload,
    )
    .await
    {
        Ok(payload) => Response::new()
            .set_status_code(StatusCode::Changed)
            .set_payload(payload),
        Err(err) => err.into_response(),
    }
}

/// A ready-to-mount `MethodRouter` handling POST requests at `EDHOC_WELL_KNOWN_PATH`. Shorthand
/// for `post(edhoc_route_handler)`.
pub fn edhoc_route() -> MethodRouter<EdhocRouterState> {
    post(edhoc_route_handler)
}
