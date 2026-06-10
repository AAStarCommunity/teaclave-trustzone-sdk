// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use crate::SecureStorageDb;
use crate::Storable;
use anyhow::{anyhow, Result};
use optee_utee::ObjectStorageConstants;
use std::{
    string::ToString,
    collections::HashMap,
    convert::TryFrom,
    hash::Hash,
    sync::{Arc, RwLock},
};

// SecureStorageClient is a client to interact with SecureStorageDb.
// Bound operations to Structure that implements Storable trait.

pub struct SecureStorageClient {
    db: Arc<RwLock<SecureStorageDb>>,
}

impl SecureStorageClient {
    /// Open a REE-FS backed database (legacy default).
    pub fn open(db_name: &str) -> Result<Self> {
        Ok(Self {
            db: Arc::new(RwLock::new(SecureStorageDb::open(db_name.to_string())?)),
        })
    }

    /// Open an RPMB-backed database.
    /// RPMB provides hardware-protected anti-replay / anti-rollback storage:
    /// data is authenticated via HMAC-SHA256 and stored in the eMMC RPMB
    /// partition, which cannot be rolled back even with direct NAND access.
    pub fn open_rpmb(db_name: &str) -> Result<Self> {
        Ok(Self {
            db: Arc::new(RwLock::new(SecureStorageDb::open_rpmb(db_name.to_string())?)),
        })
    }

    /// Open RPMB database, migrating existing REE-FS entries if migration is
    /// not yet complete.
    ///
    /// On first call after a firmware upgrade, the RPMB database will be empty
    /// while the REE-FS database has existing wallet data. This method detects
    /// that situation and transparently migrates all entries, then deletes the
    /// REE-FS copy. Safe to call on a device that was already migrated (no-op).
    ///
    /// C-1 (crash-safety / idempotency): the migration is performed in three
    /// phases so that a crash at any point leaves a recoverable state and a
    /// re-run completes safely:
    ///
    ///   1. For each REE-FS key, copy it to RPMB only if it is not already
    ///      present in RPMB (per-entry idempotent — a crash mid-copy just
    ///      re-copies the missing tail on the next boot).
    ///   2. Write a `MIGRATION_MARKER_KEY` object into RPMB. Its presence is
    ///      the authoritative "all entries copied" signal.
    ///   3. Only after the marker exists do we wipe REE-FS.
    ///
    /// The previous implementation keyed the decision off `rpmb_db.is_empty()`
    /// and wiped REE-FS immediately after the copy loop. A crash after some
    /// (but not all) `put`s left RPMB non-empty, so the next boot saw
    /// `is_empty() == false`, skipped migration entirely, and orphaned the
    /// un-copied wallets in REE-FS. The marker fixes this: migration is only
    /// considered done when the marker is present, and REE-FS is only wiped
    /// once the marker is durably written.
    pub fn open_rpmb_migrating(db_name: &str) -> Result<Self> {
        // Internal key marking migration completion. Stored with a raw key (no
        // "TableName#key" prefix), so it cannot collide with any Storable entry
        // (Storable::storage_key always contains a '#' separator).
        const MIGRATION_MARKER_KEY: &str = "__rpmb_migration_complete_v1";

        let mut rpmb_db = SecureStorageDb::open_rpmb(db_name.to_string())?;

        // If the marker is present, migration already finished — fast path.
        // get() returns Err on not-found; treat any error as "marker absent".
        let migration_done = rpmb_db.get(MIGRATION_MARKER_KEY).is_ok();

        if !migration_done {
            let mut ree_db = SecureStorageDb::open(db_name.to_string())?;
            if !ree_db.is_empty() {
                // Phase 1: per-entry idempotent copy. Only copy keys that are
                // not already in RPMB, so a re-run after a partial copy resumes
                // rather than duplicating or skipping.
                let all = ree_db.list_entries_with_prefix("")?;
                for (k, v) in &all {
                    if k.as_str() == MIGRATION_MARKER_KEY {
                        continue;
                    }
                    if rpmb_db.get(k.as_str()).is_err() {
                        rpmb_db.put(k.clone(), v.clone())?;
                    }
                }
                // Phase 2: durably mark migration complete BEFORE wiping REE-FS.
                rpmb_db.put(MIGRATION_MARKER_KEY.to_string(), vec![1u8])?;
                // Phase 3: only now is it safe to wipe the REE-FS source copy.
                ree_db.clear()?;
            } else {
                // No REE-FS data to migrate (fresh device or already wiped).
                // Still write the marker so subsequent boots take the fast path
                // and never re-enter this branch.
                rpmb_db.put(MIGRATION_MARKER_KEY.to_string(), vec![1u8])?;
            }
        }

        Ok(Self { db: Arc::new(RwLock::new(rpmb_db)) })
    }

    pub fn open_with_storage(db_name: &str, storage: ObjectStorageConstants) -> Result<Self> {
        Ok(Self {
            db: Arc::new(RwLock::new(
                SecureStorageDb::open_with_storage(db_name.to_string(), storage)?,
            )),
        })
    }

    pub fn get<V>(&self, key: &V::Key) -> Result<V>
    where
        V: Storable + serde::de::DeserializeOwned,
        V::Key: ToString,
    {
        let key = key.to_string();
        let storage_key = V::concat_key(&key);
        let value = self
            .db
            .read()
            .map_err(|_| anyhow!("Failed to acquire read lock"))?
            .get(&storage_key)?;
        Ok(bincode::deserialize(&value)?)
    }

    pub fn put<V>(&self, value: &V) -> Result<()>
    where
        V: Storable + serde::Serialize,
    {
        let key = value.storage_key();
        let value = bincode::serialize(value)?;
        self.db
            .write()
            .map_err(|_| anyhow!("Failed to acquire write lock"))?
            .put(key, value)?;
        Ok(())
    }

    pub fn delete_entry<V>(&self, key: &V::Key) -> Result<()>
    where
        V: Storable,
        V::Key: ToString,
    {
        let key = key.to_string();
        let storage_key = V::concat_key(&key);
        self.db
            .write()
            .map_err(|_| anyhow!("Failed to acquire write lock"))?
            .delete(&storage_key)?;
        Ok(())
    }

    /// Count entries for a Storable type without deserializing them or requiring
    /// `Key: TryFrom<String>`. Used for cheap quota checks (e.g. wallet caps).
    pub fn count_entries<V>(&self) -> Result<usize>
    where
        V: Storable,
    {
        let map = self
            .db
            .read()
            .map_err(|_| anyhow!("Failed to acquire read lock"))?
            .list_entries_with_prefix(V::table_name())?;
        Ok(map.len())
    }

    pub fn list_entries<V>(&self) -> Result<HashMap<V::Key, V>>
    where
        V: Storable + serde::de::DeserializeOwned,
        V::Key: TryFrom<String> + Eq + Hash,
    {
        let map = self
            .db
            .read()
            .map_err(|_| anyhow!("Failed to acquire read lock"))?
            .list_entries_with_prefix(V::table_name())?;
        let mut result = HashMap::new();
        for (_k, v) in map {
            let value: V = bincode::deserialize(&v)?;
            let key = value.unique_id();
            result.insert(key, value);
        }
        Ok(result)
    }
}
