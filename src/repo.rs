use crate::db::Account;
use crate::db::Db;
use crate::db::Status;
use crate::nauthz_grpc::Event;
use crate::Users;
use anyhow::Result;

use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Repo {
    db: Arc<Mutex<Db>>,
}

impl Repo {
    pub fn new(db_path: Option<String>) -> Result<Self> {
        Ok(Repo {
            db: Arc::new(Mutex::new(Db::new(db_path)?)),
        })
    }

    pub fn add_account(&self, account: &Account) -> Result<()> {
        self.db.lock().unwrap().write_account(account)
    }

    pub fn get_account(&self, pubkey: &str) -> Result<Option<Account>> {
        self.db.lock().unwrap().read_account(pubkey)
    }

    pub async fn update_account(&self, pubkey: &str, status: Status) -> Result<Account> {
        let account = Account {
            pubkey: pubkey.to_string(),
            status,
        };

        self.db.lock().unwrap().write_account(&account)?;

        Ok(account)
    }

    pub fn get_all_accounts(&self) -> Result<()> {
        self.db.lock().unwrap().read_all_accounts()
    }

    pub fn get_accounts(&self) -> Result<Users> {
        self.db.lock().unwrap().read_accounts()
    }

    pub async fn admit_pubkeys(&self, pubkeys: &[String]) -> Result<()> {
        for pubkey in pubkeys {
            // Really basic check that its a key
            // Would like to test better
            if pubkey.len() == 64 {
                self.update_account(pubkey, Status::Allow).await.ok();
            }
        }
        Ok(())
    }

    pub async fn deny_pubkeys(&self, pubkeys: &[String]) -> Result<()> {
        for pubkey in pubkeys {
            self.update_account(pubkey, Status::Deny).await.ok();
        }
        Ok(())
    }

    pub async fn handle_admission_update(&self, event: Event) -> Result<()> {
        for tag in event.tags {
            match tag.values.get(0) {
                Some(value) if value.as_str() == "allow" => {
                    self.admit_pubkeys(
                        &tag.values
                            .split_first()
                            .map(|(_, rest)| rest.to_vec())
                            .unwrap_or(Vec::new()),
                    )
                    .await?
                }
                Some(value) if value.as_str() == "deny" => {
                    self.deny_pubkeys(
                        &tag.values
                            .split_first()
                            .map(|(_, rest)| rest.to_vec())
                            .unwrap_or(Vec::new()),
                    )
                    .await?
                }
                _ => continue,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use serial_test::serial;

    use crate::nauthz_grpc::event::TagEntry;

    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_handle_admission_event() {
        let allowed_keys = vec![
            "allow".to_string(),
            "9dc4e4790da6e1f00285c493ba491bfda3c3cba0c4511ac60ddadd6e74cdc31c".to_string(),
            "9dc4e4790da6e1f00285c493ba491bfda3c3cba0c4511ac60ddadd6e74cdc31c".to_string(),
            "09f15c13dc7e0ce57041ed7eefea6d9927d10d9c1cc8eb8348dff19a799baa1a".to_string(),
            "".to_string(),
        ];

        let denied_keys = vec![
            "deny".to_string(),
            "0c0c1cc2cef014a8c1dcdab84754de813501e8648ecddb931145486b6fe84bdb".to_string(),
            "2eb604f41ee770a9c0479ca371ffe1fd6aa169b64ec37c0de128001152e06c04".to_string(),
        ];

        let repo = Repo::new(None).unwrap();
        let event = Event {
            id: vec![],
            pubkey: vec![],
            created_at: 172782,
            kind: 4242,
            content: "".to_string(),
            tags: vec![
                TagEntry {
                    values: allowed_keys.clone(),
                },
                TagEntry {
                    values: denied_keys.clone(),
                },
            ],
            sig: vec![],
        };

        repo.handle_admission_update(event).await.unwrap();

        assert_eq!(
            true,
            repo.get_account(&allowed_keys[1])
                .unwrap()
                .unwrap()
                .is_admitted()
        );

        assert_eq!(
            true,
            repo.get_account(&allowed_keys[2])
                .unwrap()
                .unwrap()
                .is_admitted()
        );

        assert_eq!(
            false,
            repo.get_account(&denied_keys[1])
                .unwrap()
                .unwrap()
                .is_admitted()
        );

        assert_eq!(
            false,
            repo.get_account(&denied_keys[2])
                .unwrap()
                .unwrap()
                .is_admitted()
        );
    }
}
