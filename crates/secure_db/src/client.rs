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

    /// Open RPMB database, migrating existing REE-FS entries if RPMB is empty.
    ///
    /// On first call after a firmware upgrade, the RPMB database will be empty
    /// while the REE-FS database has existing wallet data. This method detects
    /// that situation and transparently migrates all entries, then deletes the
    /// REE-FS copy. Safe to call on a device that was already migrated (no-op).
    pub fn open_rpmb_migrating(db_name: &str) -> Result<Self> {
        let rpmb_db = SecureStorageDb::open_rpmb(db_name.to_string())?;
        if rpmb_db.is_empty() {
            // Check whether REE-FS has data to migrate
            let mut ree_db = SecureStorageDb::open(db_name.to_string())?;
            if !ree_db.is_empty() {
                // Collect all REE-FS entries; migrate to RPMB one by one.
                // We cannot call list_entries_with_prefix because we don't know
                // the prefix here — use the raw prefix "" to get everything.
                let all = ree_db.list_entries_with_prefix("")?;
                let mut rpmb = SecureStorageDb::open_rpmb(db_name.to_string())?;
                for (k, v) in &all {
                    rpmb.put(k.clone(), v.clone())?;
                }
                // Wipe REE-FS after successful RPMB write
                ree_db.clear()?;
                return Ok(Self { db: Arc::new(RwLock::new(rpmb)) });
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
