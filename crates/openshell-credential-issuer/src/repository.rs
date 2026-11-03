// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Issuer-owned persistence, independent of gateway records and serialization.

use crate::auth::GatewayScope;

mod backend_objects;
pub mod grants;
pub mod references;
use sqlx::{Any, AnyPool, Row, Transaction, any::AnyPoolOptions};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use tonic::Status;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Backend {
    Sqlite,
    Postgres,
}
#[derive(Clone)]
pub struct Repository {
    pool: AnyPool,
    lock_pool: Option<AnyPool>,
    backend: Backend,
}
impl std::fmt::Debug for Repository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuerRepository(<redacted>)")
    }
}
#[derive(Clone, Debug)]
pub struct ScopedRepository {
    repository: Arc<Repository>,
    namespace: String,
    creator: String,
}
#[derive(Clone)]
pub struct Record {
    pub revision: u64,
    pub payload: Vec<u8>,
}
impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("revision", &self.revision)
            .field("payload", &"<redacted>")
            .finish()
    }
}
#[derive(Clone)]
pub enum Mutation {
    Put {
        kind: String,
        key: String,
        expected: Option<u64>,
        payload: Vec<u8>,
    },
    Delete {
        kind: String,
        key: String,
        expected: u64,
    },
    Check {
        kind: String,
        key: String,
        expected: u64,
    },
}
impl Mutation {
    fn key(&self) -> (&str, &str) {
        match self {
            Self::Put { kind, key, .. }
            | Self::Delete { kind, key, .. }
            | Self::Check { kind, key, .. } => (kind, key),
        }
    }
}
/// Durable value-free event. The sequence is namespace-wide, not a value version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub kind: String,
    pub key: String,
    pub version: u64,
    pub deleted: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub sequence: u64,
    pub change: Change,
}
#[derive(Debug)]
pub struct CommitReceipt {
    pub revisions: BTreeMap<(String, String), u64>,
    pub last_sequence: Option<u64>,
}

// Dropping an SQLx transaction schedules rollback before its pooled connection
// can be reused. PG advisory locks belong to that transaction, never a session
// accidentally returned to the data pool. SQLite uses engine-local exclusion.
pub struct RefreshLease {
    _transaction: Option<Transaction<'static, Any>>,
}

fn unavailable(_: sqlx::Error) -> Status {
    Status::unavailable("issuer persistence operation failed")
}
fn signed(value: u64) -> Result<i64, Status> {
    i64::try_from(value).map_err(|_| Status::out_of_range("issuer storage revision exceeds range"))
}
fn unsigned(value: i64) -> Result<u64, Status> {
    u64::try_from(value).map_err(|_| Status::data_loss("invalid issuer storage revision"))
}
fn valid_key(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
}

impl Repository {
    pub async fn open(url: &str) -> Result<Arc<Self>, Status> {
        let backend = if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            Backend::Postgres
        } else if url.starts_with("sqlite:") {
            Backend::Sqlite
        } else {
            return Err(Status::invalid_argument(
                "issuer database must use sqlite or postgres",
            ));
        };
        sqlx::any::install_default_drivers();
        let sqlite = backend == Backend::Sqlite;
        let pool = AnyPoolOptions::new()
            .max_connections(if url.contains(":memory:") { 1 } else { 16 })
            .acquire_timeout(Duration::from_secs(10))
            .after_connect(move |connection, _| {
                Box::pin(async move {
                    if sqlite {
                        sqlx::query("PRAGMA busy_timeout = 5000")
                            .execute(connection)
                            .await?;
                    }
                    Ok(())
                })
            })
            .connect(url)
            .await
            .map_err(unavailable)?;
        let lock_pool = if sqlite {
            None
        } else {
            Some(
                AnyPoolOptions::new()
                    .max_connections(8)
                    .acquire_timeout(Duration::from_secs(40))
                    .connect_lazy(url)
                    .map_err(unavailable)?,
            )
        };
        let repository = Arc::new(Self {
            pool,
            lock_pool,
            backend,
        });
        repository.initialize().await?;
        Ok(repository)
    }
    pub fn for_gateway(self: &Arc<Self>, scope: &GatewayScope) -> ScopedRepository {
        ScopedRepository {
            repository: self.clone(),
            namespace: scope.namespace().to_string(),
            creator: scope.identity().to_string(),
        }
    }
    pub fn is_postgres(&self) -> bool {
        self.backend == Backend::Postgres
    }
    async fn initialize(&self) -> Result<(), Status> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        if self.is_postgres() {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('openshell.credential-issuer.schema.v1',0))::text")
                .fetch_one(&mut *tx).await.map_err(unavailable)?;
        }
        sqlx::query("CREATE TABLE IF NOT EXISTS issuer_schema (id INTEGER PRIMARY KEY, version INTEGER NOT NULL)").execute(&mut *tx).await.map_err(unavailable)?;
        sqlx::query("INSERT INTO issuer_schema (id, version) VALUES (1, 1) ON CONFLICT DO NOTHING")
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        let row = sqlx::query("SELECT version FROM issuer_schema WHERE id = 1")
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        if row.try_get::<i32, _>("version").map_err(unavailable)? != 1 {
            return Err(Status::failed_precondition(
                "unsupported issuer database schema",
            ));
        }
        let objects_ddl = if self.is_postgres() {
            "CREATE TABLE IF NOT EXISTS issuer_objects (namespace TEXT NOT NULL, creator TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, revision BIGINT NOT NULL, payload BYTEA NOT NULL, PRIMARY KEY(namespace, kind, id))"
        } else {
            "CREATE TABLE IF NOT EXISTS issuer_objects (namespace TEXT NOT NULL, creator TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, revision BIGINT NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(namespace, kind, id))"
        };
        sqlx::query(objects_ddl)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::query("CREATE TABLE IF NOT EXISTS issuer_sequences (namespace TEXT PRIMARY KEY, creator TEXT NOT NULL, sequence BIGINT NOT NULL)").execute(&mut *tx).await.map_err(unavailable)?;
        sqlx::query("CREATE TABLE IF NOT EXISTS issuer_events (namespace TEXT NOT NULL, creator TEXT NOT NULL, sequence BIGINT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, version TEXT NOT NULL, deleted INTEGER NOT NULL, PRIMARY KEY(namespace, sequence))").execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
}

impl ScopedRepository {
    pub async fn load(&self, kind: &str, key: &str) -> Result<Option<Record>, Status> {
        let row = sqlx::query("SELECT revision, payload FROM issuer_objects WHERE namespace=$1 AND creator=$2 AND kind=$3 AND id=$4")
            .bind(&self.namespace).bind(&self.creator).bind(kind).bind(key).fetch_optional(&self.repository.pool).await.map_err(unavailable)?;
        row.map(|row| {
            Ok(Record {
                revision: unsigned(row.try_get("revision").map_err(unavailable)?)?,
                payload: row.try_get("payload").map_err(unavailable)?,
            })
        })
        .transpose()
    }
    pub async fn list(
        &self,
        kind: &str,
        after_key: Option<&str>,
        limit: u32,
    ) -> Result<Vec<(String, Record)>, Status> {
        if limit == 0 || limit > 1024 {
            return Err(Status::invalid_argument("invalid issuer object page size"));
        }
        let rows = sqlx::query("SELECT id, revision, payload FROM issuer_objects WHERE namespace=$1 AND creator=$2 AND kind=$3 AND id>$4 ORDER BY id LIMIT $5")
            .bind(&self.namespace).bind(&self.creator).bind(kind).bind(after_key.unwrap_or("")).bind(i64::from(limit)).fetch_all(&self.repository.pool).await.map_err(unavailable)?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    row.try_get("id").map_err(unavailable)?,
                    Record {
                        revision: unsigned(row.try_get("revision").map_err(unavailable)?)?,
                        payload: row.try_get("payload").map_err(unavailable)?,
                    },
                ))
            })
            .collect()
    }
    /// Every check, write, event, and sequence advance commits together or none
    /// does. Lock keys in canonical order to avoid cross-output deadlocks.
    pub async fn commit(
        &self,
        mutations: &[Mutation],
        changes: &[Change],
    ) -> Result<CommitReceipt, Status> {
        if mutations.is_empty() || mutations.len() > 1024 || changes.len() > 1024 {
            return Err(Status::invalid_argument("invalid issuer transaction size"));
        }
        let mut keys = BTreeSet::new();
        for mutation in mutations {
            let (kind, key) = mutation.key();
            if !valid_key(kind) || !valid_key(key) || !keys.insert((kind, key)) {
                return Err(Status::invalid_argument(
                    "invalid or duplicate issuer mutation key",
                ));
            }
        }
        if changes.iter().any(|change| {
            !valid_key(&change.kind) || !valid_key(&change.key) || change.version == 0
        }) {
            return Err(Status::invalid_argument("invalid issuer change event"));
        }
        let mut ordered = mutations.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|mutation| mutation.key());
        let mut tx = if self.repository.is_postgres() {
            self.repository.pool.begin().await
        } else {
            self.repository.pool.begin_with("BEGIN IMMEDIATE").await
        }
        .map_err(unavailable)?;
        let mut revisions = BTreeMap::new();
        for mutation in ordered {
            let (kind, key) = mutation.key();
            let revision = match mutation {
                Mutation::Put {
                    expected: None,
                    payload,
                    ..
                } => {
                    let result = sqlx::query("INSERT INTO issuer_objects (namespace,creator,kind,id,revision,payload) VALUES ($1,$2,$3,$4,1,$5) ON CONFLICT DO NOTHING")
                        .bind(&self.namespace).bind(&self.creator).bind(kind).bind(key).bind(payload).execute(&mut *tx).await.map_err(unavailable)?;
                    if result.rows_affected() != 1 {
                        return Err(Status::already_exists("issuer object already exists"));
                    }
                    1
                }
                Mutation::Put {
                    expected: Some(expected),
                    payload,
                    ..
                } => {
                    let next = signed(*expected)?
                        .checked_add(1)
                        .ok_or_else(|| Status::out_of_range("issuer storage revision exhausted"))?;
                    let result = sqlx::query("UPDATE issuer_objects SET revision=$1, payload=$2 WHERE namespace=$3 AND creator=$4 AND kind=$5 AND id=$6 AND revision=$7")
                        .bind(next).bind(payload).bind(&self.namespace).bind(&self.creator).bind(kind).bind(key).bind(signed(*expected)?).execute(&mut *tx).await.map_err(unavailable)?;
                    if result.rows_affected() != 1 {
                        return Err(Status::aborted("issuer object revision changed"));
                    }
                    unsigned(next)?
                }
                Mutation::Delete { expected, .. } => {
                    let result = sqlx::query("DELETE FROM issuer_objects WHERE namespace=$1 AND creator=$2 AND kind=$3 AND id=$4 AND revision=$5")
                        .bind(&self.namespace).bind(&self.creator).bind(kind).bind(key).bind(signed(*expected)?).execute(&mut *tx).await.map_err(unavailable)?;
                    if result.rows_affected() != 1 {
                        return Err(Status::aborted("issuer object revision changed"));
                    }
                    0
                }
                Mutation::Check { expected, .. } => {
                    let query = if self.repository.is_postgres() {
                        "SELECT revision FROM issuer_objects WHERE namespace=$1 AND creator=$2 AND kind=$3 AND id=$4 FOR UPDATE"
                    } else {
                        "SELECT revision FROM issuer_objects WHERE namespace=$1 AND creator=$2 AND kind=$3 AND id=$4"
                    };
                    let row = sqlx::query(query)
                        .bind(&self.namespace)
                        .bind(&self.creator)
                        .bind(kind)
                        .bind(key)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(unavailable)?;
                    let revision = row
                        .map(|row| row.try_get::<i64, _>("revision"))
                        .transpose()
                        .map_err(unavailable)?;
                    if revision != Some(signed(*expected)?) {
                        return Err(Status::aborted("issuer object revision changed"));
                    }
                    *expected
                }
            };
            revisions.insert((kind.to_string(), key.to_string()), revision);
        }
        let mut last_sequence = None;
        for change in changes {
            sqlx::query("INSERT INTO issuer_sequences(namespace,creator,sequence) VALUES($1,$2,0) ON CONFLICT DO NOTHING")
                .bind(&self.namespace).bind(&self.creator).execute(&mut *tx).await.map_err(unavailable)?;
            let row = sqlx::query("UPDATE issuer_sequences SET sequence=sequence+1 WHERE namespace=$1 AND creator=$2 AND sequence<9223372036854775807 RETURNING sequence")
                .bind(&self.namespace).bind(&self.creator).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or_else(|| Status::out_of_range("issuer change sequence exhausted"))?;
            let sequence: i64 = row.try_get("sequence").map_err(unavailable)?;
            sqlx::query("INSERT INTO issuer_events(namespace,creator,sequence,kind,id,version,deleted) VALUES($1,$2,$3,$4,$5,$6,$7)")
                .bind(&self.namespace).bind(&self.creator).bind(sequence).bind(&change.kind).bind(&change.key).bind(change.version.to_string()).bind(i32::from(change.deleted)).execute(&mut *tx).await.map_err(unavailable)?;
            last_sequence = Some(unsigned(sequence)?);
        }
        tx.commit().await.map_err(unavailable)?;
        Ok(CommitReceipt {
            revisions,
            last_sequence,
        })
    }
    pub async fn current_sequence(&self) -> Result<u64, Status> {
        let row =
            sqlx::query("SELECT sequence FROM issuer_sequences WHERE namespace=$1 AND creator=$2")
                .bind(&self.namespace)
                .bind(&self.creator)
                .fetch_optional(&self.repository.pool)
                .await
                .map_err(unavailable)?;
        row.map(|row| unsigned(row.try_get("sequence").map_err(unavailable)?))
            .transpose()
            .map(|value| value.unwrap_or(0))
    }
    pub async fn events_after(&self, sequence: u64, limit: u32) -> Result<Vec<Event>, Status> {
        if limit == 0 || limit > 1024 {
            return Err(Status::invalid_argument("invalid issuer event page size"));
        }
        let rows = sqlx::query("SELECT sequence,kind,id,version,deleted FROM issuer_events WHERE namespace=$1 AND creator=$2 AND sequence>$3 ORDER BY sequence LIMIT $4")
            .bind(&self.namespace).bind(&self.creator).bind(signed(sequence)?).bind(i64::from(limit)).fetch_all(&self.repository.pool).await.map_err(unavailable)?;
        rows.into_iter()
            .map(|row| {
                let version: String = row.try_get("version").map_err(unavailable)?;
                Ok(Event {
                    sequence: unsigned(row.try_get("sequence").map_err(unavailable)?)?,
                    change: Change {
                        kind: row.try_get("kind").map_err(unavailable)?,
                        key: row.try_get("id").map_err(unavailable)?,
                        version: version
                            .parse()
                            .map_err(|_| Status::data_loss("invalid issuer event version"))?,
                        deleted: row.try_get::<i32, _>("deleted").map_err(unavailable)? != 0,
                    },
                })
            })
            .collect()
    }
    pub async fn try_refresh_lease(&self, grant: &str) -> Result<Option<RefreshLease>, Status> {
        if !valid_key(grant) {
            return Err(Status::invalid_argument("invalid issuer grant lock key"));
        }
        let Some(pool) = &self.repository.lock_pool else {
            return Ok(Some(RefreshLease { _transaction: None }));
        };
        let mut tx = pool.begin().await.map_err(unavailable)?;
        let row =
            sqlx::query("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0)) AS acquired")
                .bind(format!("{}:{grant}", self.namespace))
                .fetch_one(&mut *tx)
                .await
                .map_err(unavailable)?;
        if !row.try_get::<bool, _>("acquired").map_err(unavailable)? {
            return Ok(None);
        }
        Ok(Some(RefreshLease {
            _transaction: Some(tx),
        }))
    }
    pub async fn acquire_refresh_lease(&self, grant: &str) -> Result<RefreshLease, Status> {
        if !valid_key(grant) {
            return Err(Status::invalid_argument("invalid issuer grant lock key"));
        }
        let Some(pool) = &self.repository.lock_pool else {
            return Ok(RefreshLease { _transaction: None });
        };
        let mut tx = pool.begin().await.map_err(unavailable)?;
        sqlx::query("SET LOCAL lock_timeout = '40s'")
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        // PostgreSQL hashing is for coordination, not authentication. Collisions
        // serialize unrelated grants; they cannot bypass identity or CAS fences.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))::text")
            .bind(format!("{}:{grant}", self.namespace))
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        Ok(RefreshLease {
            _transaction: Some(tx),
        })
    }
}

#[cfg(test)]
mod tests;
