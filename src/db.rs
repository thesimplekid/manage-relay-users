use anyhow::Result;
use redb::{Database, ReadableTable, TableDefinition};
use tracing::debug;

use crate::Users;

// key is hex pubkey value is name
const ACCOUNTTABLE: TableDefinition<&str, u8> = TableDefinition::new("account");

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum Status {
    Deny,
    Allow,
}

impl Status {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Status::Deny,
            1 => Status::Allow,
            // This should never happen
            _ => Status::Deny,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Account {
    pub pubkey: String,
    pub status: Status,
}

impl Account {
    pub fn is_admitted(&self) -> bool {
        if self.status.eq(&Status::Allow) {
            return true;
        }
        false
    }
}

pub struct Db {
    db: Database,
}

impl Db {
    pub fn new(db_path: Option<String>) -> Result<Self> {
        debug!("Creating DB");

        let db_path = db_path.unwrap_or("manage_users.redb".to_string());
        let db = Database::create(db_path)?;
        let write_txn = db.begin_write()?;
        {
            // Opens the table to create it
            let _ = write_txn.open_table(ACCOUNTTABLE)?;
        }
        write_txn.commit()?;

        Ok(Self { db })
    }

    pub fn write_account(&self, account: &Account) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(ACCOUNTTABLE)?;
            table.insert(account.pubkey.as_str(), account.status as u8)?;
        }
        write_txn.commit().unwrap();
        Ok(())
    }

    pub fn read_account(&self, pubkey: &str) -> Result<Option<Account>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ACCOUNTTABLE)?;
        if let Some(account_info) = table.get(pubkey)? {
            let account = Account {
                pubkey: pubkey.to_string(),
                status: Status::from_u8(account_info.value()),
            };
            return Ok(Some(account));
        }
        Ok(None)
    }

    pub fn read_all_accounts(&self) -> Result<()> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ACCOUNTTABLE)?;

        for a in table.iter()? {
            let a = a?;
            debug!("{:?}, {}", a.0.value(), a.1.value());
        }
        Ok(())
    }

    pub fn read_accounts(&self) -> Result<Users> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ACCOUNTTABLE)?;

        let users: Vec<(String, u8)> = table
            .iter()?
            .flatten()
            .map(|(k, s)| (k.value().to_string(), s.value()))
            .collect();

        let (allow, deny): (Vec<String>, Vec<String>) =
            users
                .iter()
                .map(|(s, i)| (s, *i))
                .fold((Vec::new(), Vec::new()), |mut acc, (s, i)| {
                    match i {
                        1 => acc.0.push(s.to_owned()),
                        0 => acc.1.push(s.to_owned()),
                        _ => {}
                    }
                    acc
                });

        Ok(Users {
            allow: Some(allow),
            deny: Some(deny),
        })
    }

    pub fn clear_tables(&self) -> Result<()> {
        let write_txn = self.db.begin_write()?;

        {
            let mut table = write_txn.open_table(ACCOUNTTABLE)?;
            while table.len()? > 0 {
                let _ = table.pop_first();
            }
        }
        write_txn.commit().unwrap();

        Ok(())
    }
}
