mod cve_2022_33647;
mod cve_2023_28244;
mod downgrade_pa;
mod roast_active;
mod roast_passive;

pub use cve_2022_33647::Cve202233647Handler;
pub use cve_2023_28244::Cve202328244Handler;
pub use downgrade_pa::DowngradePaHandler;
pub use roast_active::RoastActiveHandler;
pub use roast_passive::RoastPassiveHandler;

use kile::KdcFrame;

/// An action that a Handler can perform
pub enum HandlerAction {
    /// Forward a (possibly modified) message
    Forward(KdcFrame),
    /// Drop the in-flight message and reply to sender with a new message
    DropAndReplyWith(KdcFrame),
    /// Drop the in-flight message silently
    DropSilently,
}

/// A conposable component of kdc-proxy that can be enabled or disabled
///
/// A Handler can:
/// - passively listen to traffic (ex. dump AsReq/AsRep for Roasting)
/// - modify traffic before passing along
/// - replay traffic, or send arbitrary additional messages?
pub trait Handler
where
    Self: Send + 'static,
{
    /// Name of the handler plugin
    fn name(&self) -> &'static str;

    /// Handle requests from the Kerberos client (AS_REQ and TGS_REQ)
    ///
    /// The handler is able to inspect the request and either:
    /// - pass along unmodified
    /// - pass along with modifications
    /// - drop the request and send an error response to the client
    /// - drop the request silently
    fn handle_downstream(&mut self, frame: KdcFrame) -> HandlerAction;

    /// Handle replies from the KDC (AS_REP, TGS_REP, and KRB_ERROR)
    ///
    /// The handler is able to inspect the reply and either:
    /// - pass along unmodified
    /// - pass along with modifications
    /// - drop the reply and send a different request to the KDC
    /// - drop the reply silenty
    fn handle_upstream(&mut self, frame: KdcFrame) -> HandlerAction;
}

/// Example handler that performs no actions and passes messages along unmodified
#[derive(Clone, Copy)]
pub struct IdentityHandler;

impl Handler for IdentityHandler {
    fn name(&self) -> &'static str {
        "IDENTITY"
    }

    fn handle_downstream(&mut self, frame: KdcFrame) -> HandlerAction {
        HandlerAction::Forward(frame)
    }

    fn handle_upstream(&mut self, frame: KdcFrame) -> HandlerAction {
        HandlerAction::Forward(frame)
    }
}

/// Example handler that performs no actions and drops all messages silently
#[derive(Clone, Copy)]
struct NullHandler;

impl Handler for NullHandler {
    fn name(&self) -> &'static str {
        "NULL"
    }

    fn handle_downstream(&mut self, frame: KdcFrame) -> HandlerAction {
        drop(frame);
        HandlerAction::DropSilently
    }

    fn handle_upstream(&mut self, frame: KdcFrame) -> HandlerAction {
        drop(frame);
        HandlerAction::DropSilently
    }
}
