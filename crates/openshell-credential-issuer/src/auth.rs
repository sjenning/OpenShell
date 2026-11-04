// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Issuer caller scoping. Request metadata never supplies a gateway identity.

use crate::SecretOwner;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use tonic::{
    Request, Status,
    transport::server::{TcpConnectInfo, TlsConnectInfo},
};

/// Exact certificate URI identities mapped to explicitly allowed workspaces.
/// The listener must verify client chains against its configured trust roots.
#[derive(Debug, Clone)]
pub struct GatewayPolicy {
    bindings: BTreeMap<String, BTreeSet<String>>,
    local: Option<GatewayScope>,
}

/// Authorized caller derived from TLS or the private typed local transport,
/// never a user-supplied owner or header.
#[derive(Debug, Clone)]
pub struct GatewayScope {
    identity: String,
    namespace: String,
    workspaces: BTreeSet<String>,
    local: bool,
}

const LOCAL_GATEWAY_IDENTITY: &str = "spiffe://openshell.local/gateway/embedded";

// This type and its constructor are not public API. HTTP metadata cannot
// manufacture a typed request extension; only the embedded transport adds it.
#[derive(Clone)]
pub(crate) struct LocalGateway(());

pub(crate) fn local_request<T>(mut request: Request<T>) -> Request<T> {
    request.extensions_mut().insert(LocalGateway(()));
    request
}

fn valid_workspace(workspace: &str) -> bool {
    !workspace.is_empty()
        && workspace.len() <= 128
        && workspace.trim() == workspace
        && !workspace.contains('*')
        && !workspace.chars().any(char::is_control)
}

impl GatewayPolicy {
    pub fn new(bindings: BTreeMap<String, Vec<String>>) -> Result<Self, Status> {
        if bindings.is_empty() {
            return Err(Status::invalid_argument(
                "issuer gateway identity bindings are required",
            ));
        }
        let mut validated = BTreeMap::new();
        for (identity, workspaces) in bindings {
            let parsed: spiffe::SpiffeId = identity.parse().map_err(|_| {
                Status::invalid_argument("invalid issuer gateway certificate URI identity")
            })?;
            if parsed.to_string() != identity
                || workspaces.is_empty()
                || workspaces
                    .iter()
                    .any(|workspace| !valid_workspace(workspace))
            {
                return Err(Status::invalid_argument(
                    "issuer gateway bindings require canonical identities and explicit workspaces",
                ));
            }
            validated.insert(identity, workspaces.into_iter().collect());
        }
        Ok(Self {
            bindings: validated,
            local: None,
        })
    }

    /// Local hosting uses a fixed identity and validates workspace names on
    /// every operation. It never enables wildcard certificate bindings.
    pub(crate) fn embedded() -> Result<Self, Status> {
        Ok(Self {
            bindings: BTreeMap::new(),
            local: Some(GatewayScope {
                identity: LOCAL_GATEWAY_IDENTITY.to_string(),
                namespace: identity_namespace(LOCAL_GATEWAY_IDENTITY)?,
                workspaces: BTreeSet::new(),
                local: true,
            }),
        })
    }

    /// Remote callers require verified TLS connection info. Only embedded
    /// policies recognize the private typed local marker. Forged identity
    /// headers and owner metadata cannot select a different gateway namespace.
    pub fn authenticate<T>(&self, request: &Request<T>) -> Result<GatewayScope, Status> {
        if request.extensions().get::<LocalGateway>().is_some() {
            return self.local.clone().ok_or_else(|| {
                Status::permission_denied("embedded issuer identity is not enabled")
            });
        }
        self.scope_for_identity(verified_identity(request)?)
    }

    #[cfg(test)]
    fn scope_for_verified_certificate(&self, leaf: &[u8]) -> Result<GatewayScope, Status> {
        self.scope_for_identity(certificate_identity(leaf)?)
    }

    // Trusted background enumeration only; request handlers must authenticate
    // the TLS peer rather than selecting identity from supplied metadata.
    pub(crate) fn configured_scopes(&self) -> Result<Vec<GatewayScope>, Status> {
        if let Some(scope) = &self.local {
            return Ok(vec![scope.clone()]);
        }
        self.bindings
            .keys()
            .cloned()
            .map(|identity| self.scope_for_identity(identity))
            .collect()
    }

    fn scope_for_identity(&self, identity: String) -> Result<GatewayScope, Status> {
        let workspaces = self.bindings.get(&identity).ok_or_else(|| {
            Status::permission_denied("gateway identity is not authorized by issuer")
        })?;
        let namespace = identity_namespace(&identity)?;
        Ok(GatewayScope {
            identity,
            namespace,
            workspaces: workspaces.clone(),
            local: false,
        })
    }
}

/// Exact issuer identities permitted to call a stateless minter. This is a
/// different authorization role from gateway workspace access.
#[derive(Debug, Clone)]
pub struct IssuerPolicy {
    identities: BTreeSet<String>,
}

impl IssuerPolicy {
    pub fn new(identities: Vec<String>) -> Result<Self, Status> {
        if identities.is_empty()
            || identities.iter().any(|identity| {
                identity
                    .parse::<spiffe::SpiffeId>()
                    .map_or(true, |parsed| parsed.to_string() != *identity)
            })
        {
            return Err(Status::invalid_argument(
                "minter requires explicit canonical issuer identities",
            ));
        }
        Ok(Self {
            identities: identities.into_iter().collect(),
        })
    }
    pub fn authenticate<T>(&self, request: &Request<T>) -> Result<String, Status> {
        let identity = verified_identity(request)?;
        if !self.identities.contains(&identity) {
            return Err(Status::permission_denied(
                "issuer identity is not authorized by minter",
            ));
        }
        Ok(identity)
    }
}

// DER parsing extracts identity only; verification belongs to the listener.
// Never expose an entry point accepting unverified request-supplied bytes.
fn certificate_identity(leaf: &[u8]) -> Result<String, Status> {
    let certificate = spiffe::cert::Certificate::try_from(leaf)
        .map_err(|_| Status::unauthenticated("invalid issuer client certificate"))?;
    certificate
        .spiffe_id()
        .map(|id| id.to_string())
        .map_err(|_| {
            Status::unauthenticated("issuer client certificate requires one SPIFFE URI SAN")
        })
}
fn verified_identity<T>(request: &Request<T>) -> Result<String, Status> {
    if let Some(peer) = request
        .extensions()
        .get::<openshell_extension_core::ExtensionPeer>()
    {
        return certificate_identity(peer.certificate_der());
    }
    let info = request
        .extensions()
        .get::<TlsConnectInfo<TcpConnectInfo>>()
        .ok_or_else(|| Status::unauthenticated("issuer requires mutual TLS"))?;
    let certificates = info
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated("issuer requires a client certificate"))?;
    let leaf = certificates
        .first()
        .ok_or_else(|| Status::unauthenticated("issuer requires a client certificate"))?;
    certificate_identity(leaf.as_ref())
}

impl GatewayScope {
    pub fn identity(&self) -> &str {
        &self.identity
    }
    /// Stable storage partition across certificate/key rotations. Never derive
    /// this from a caller-supplied owner or certificate serial/fingerprint.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn authorize_workspace(&self, workspace: &str) -> Result<(), Status> {
        if self.local {
            return if valid_workspace(workspace) {
                Ok(())
            } else {
                Err(Status::invalid_argument("invalid issuer workspace"))
            };
        }
        if !self.workspaces.contains(workspace) {
            return Err(Status::permission_denied(
                "gateway is not authorized for issuer workspace",
            ));
        }
        Ok(())
    }

    pub fn authorize_owner(&self, owner: &SecretOwner) -> Result<(), Status> {
        self.authorize_workspace(&owner.workspace)?;
        if owner.provider_id.is_empty() || owner.credential_key.is_empty() {
            return Err(Status::invalid_argument(
                "issuer secret owner is incomplete",
            ));
        }
        Ok(())
    }

    /// Check the durable creating identity and immutable owner before resolving
    /// values, mutating references, or exposing grant state. A matching supplied
    /// owner never authorizes access to another gateway's object.
    pub fn authorize_bound_owner(
        &self,
        creator: &str,
        bound: &SecretOwner,
        supplied: &SecretOwner,
    ) -> Result<(), Status> {
        self.authorize_owner(supplied)?;
        if creator != self.identity || bound != supplied {
            return Err(Status::permission_denied(
                "issuer object belongs to another gateway or owner",
            ));
        }
        Ok(())
    }
}

fn identity_namespace(identity: &str) -> Result<String, Status> {
    let digest = openshell_crypto::sha256(
        format!("openshell.credential-issuer.namespace.v1\0{identity}").as_bytes(),
    )
    .map_err(|_| Status::unavailable("issuer identity namespace unavailable"))?;
    let mut namespace = String::with_capacity(64);
    for byte in digest {
        write!(namespace, "{byte:02x}").expect("writing String cannot fail");
    }
    Ok(namespace)
}

#[cfg(test)]
pub(crate) fn test_scope(identity: &str) -> GatewayScope {
    GatewayScope {
        identity: identity.to_string(),
        namespace: identity_namespace(identity).unwrap(),
        workspaces: BTreeSet::from(["default".to_string()]),
        local: false,
    }
}

#[cfg(test)]
mod tests;
