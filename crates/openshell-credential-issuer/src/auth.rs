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
}

/// Authorized caller derived from TLS, not a user-supplied owner or header.
#[derive(Debug, Clone)]
pub struct GatewayScope {
    identity: String,
    namespace: String,
    workspaces: BTreeSet<String>,
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
                || workspaces.iter().any(|workspace| {
                    workspace.is_empty()
                        || workspace.len() > 128
                        || workspace.trim() != workspace
                        || workspace.contains('*')
                        || workspace.chars().any(char::is_control)
                })
            {
                return Err(Status::invalid_argument(
                    "issuer gateway bindings require canonical identities and explicit workspaces",
                ));
            }
            validated.insert(identity, workspaces.into_iter().collect());
        }
        Ok(Self {
            bindings: validated,
        })
    }

    /// Only TLS connection info is authoritative. Forged identity headers and
    /// owner metadata cannot select a different gateway namespace.
    pub fn authenticate<T>(&self, request: &Request<T>) -> Result<GatewayScope, Status> {
        if let Some(peer) = request
            .extensions()
            .get::<openshell_extension_core::ExtensionPeer>()
        {
            return self.scope_for_verified_certificate(peer.certificate_der());
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
        self.scope_for_verified_certificate(leaf.as_ref())
    }

    // DER parsing extracts identity only; cryptographic verification belongs to
    // the TLS listener. Keep this entry point private to prevent header adapters
    // from treating arbitrary client-provided bytes as an authenticated peer.
    fn scope_for_verified_certificate(&self, leaf: &[u8]) -> Result<GatewayScope, Status> {
        let certificate = spiffe::cert::Certificate::try_from(leaf)
            .map_err(|_| Status::unauthenticated("invalid issuer client certificate"))?;
        let identity = certificate
            .spiffe_id()
            .map_err(|_| {
                Status::unauthenticated("issuer client certificate requires one SPIFFE URI SAN")
            })?
            .to_string();
        let workspaces = self.bindings.get(&identity).ok_or_else(|| {
            Status::permission_denied("gateway identity is not authorized by issuer")
        })?;
        let digest = openshell_crypto::sha256(
            format!("openshell.credential-issuer.namespace.v1\0{identity}").as_bytes(),
        )
        .map_err(|_| Status::unavailable("issuer identity namespace unavailable"))?;
        let mut namespace = String::with_capacity(64);
        for byte in digest {
            write!(namespace, "{byte:02x}").expect("writing to String cannot fail");
        }
        Ok(GatewayScope {
            identity,
            namespace,
            workspaces: workspaces.clone(),
        })
    }
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

#[cfg(test)]
pub(crate) fn test_scope(identity: &str) -> GatewayScope {
    GatewayScope {
        identity: identity.to_string(),
        namespace: format!("test-namespace:{identity}"),
        workspaces: BTreeSet::from(["default".to_string()]),
    }
}

#[cfg(test)]
mod tests;
