use std::collections::HashSet;
use std::str::FromStr;

use anyhow::Result;
use nostr_sdk::client::Client;
use nostr_sdk::key::{Keys, XOnlyPublicKey};
use nostr_sdk::prelude::*;
use nostr_sdk::prelude::{decrypt, encrypt};
use nostr_sdk::{EventBuilder, Tag};
use std::time::Duration;
use url::Url;

use crate::nauthz_grpc::event::TagEntry;
use crate::nauthz_grpc::Event;
use crate::{UserStatus, Users};

#[derive(Clone)]
pub struct Repo {
    pub key: Keys,
    pub relays: HashSet<Url>,
    pub allowed_pubkeys: HashSet<XOnlyPublicKey>,
    pub denied_pubkeys: HashSet<XOnlyPublicKey>,
}

impl Repo {
    pub fn new(key: Keys, relays: HashSet<Url>) -> Result<Self> {
        Ok(Repo {
            key,
            relays,
            allowed_pubkeys: HashSet::new(),
            denied_pubkeys: HashSet::new(),
        })
    }

    pub async fn publish_event(&self, event: nostr_sdk::event::Event) -> Result<()> {
        let relays = self.relays.iter().map(|x| (x.to_string(), None)).collect();

        let client = Client::new(&self.key);
        client.add_relays(relays).await?;

        client.send_event(event).await?;

        Ok(())
    }

    pub async fn restore_user_list(&mut self) -> Result<()> {
        let relays = self.relays.iter().map(|x| (x.to_string(), None)).collect();

        let client = Client::new(&self.key);
        client.add_relays(relays).await?;
        client.connect().await;

        let subscription = Filter::new()
            .authors(vec![self.key.public_key().to_string()])
            .identifiers(vec!["allow"])
            .kind(Kind::CategorizedPeopleList);

        let timeout = Duration::from_secs(10);
        let allow_events = client
            .get_events_of(vec![subscription], Some(timeout))
            .await?;

        if let Some(allow_event) = allow_events.iter().max_by_key(|e| e.created_at) {
            self.allowed_pubkeys = self.pubkeys_from_nostr(allow_event.to_owned())?;
        }

        let subscription = Filter::new()
            .pubkeys(vec![self.key.public_key()])
            .identifiers(vec!["deny"])
            .kind(Kind::CategorizedPeopleList);

        let timeout = Duration::from_secs(10);
        let deny_events = client
            .get_events_of(vec![subscription], Some(timeout))
            .await?;

        if let Some(deny_event) = deny_events.iter().max_by_key(|e| e.created_at) {
            self.denied_pubkeys = self.pubkeys_from_nostr(deny_event.clone())?;
        }
        Ok(())
    }

    pub async fn admit_pubkeys(&mut self, pubkeys: &HashSet<XOnlyPublicKey>) -> Result<()> {
        self.allowed_pubkeys.extend(pubkeys);
        self.denied_pubkeys = self
            .denied_pubkeys
            .iter()
            .filter(|p| !self.allowed_pubkeys.contains(p))
            .cloned()
            .collect();

        let allowed: Vec<_> = pubkeys
            .iter()
            .map(|p| Tag::PubKey(p.to_owned(), None))
            .collect();
        let json_string = serde_json::to_string(&allowed)?;

        let encrypted = encrypt(
            &self.key.secret_key().unwrap(),
            &self.key.public_key(),
            json_string,
        )?;

        let event = EventBuilder::new(
            nostr_sdk::Kind::CategorizedPeopleList,
            encrypted,
            &[Tag::Generic(
                nostr_sdk::TagKind::D,
                vec!["allow".to_string()],
            )],
        )
        .to_event(&self.key)?;

        self.publish_event(event).await?;

        Ok(())
    }

    pub async fn deny_pubkeys(&mut self, pubkeys: &HashSet<XOnlyPublicKey>) -> Result<()> {
        self.denied_pubkeys.extend(pubkeys);
        self.allowed_pubkeys = self
            .allowed_pubkeys
            .iter()
            .filter(|p| !self.denied_pubkeys.contains(p))
            .cloned()
            .collect();

        let denied: Vec<_> = pubkeys
            .iter()
            .map(|p| Tag::PubKey(p.to_owned(), None))
            .collect();
        let json_string = serde_json::to_string(&denied)?;

        let encrypted = encrypt(
            &self.key.secret_key().unwrap(),
            &self.key.public_key(),
            json_string,
        )?;

        let event = EventBuilder::new(
            nostr_sdk::Kind::CategorizedPeopleList,
            encrypted,
            &[Tag::Generic(
                nostr_sdk::TagKind::D,
                vec!["deny".to_string()],
            )],
        )
        .to_event(&self.key)?;

        self.publish_event(event).await?;

        Ok(())
    }

    pub fn get_users(&self) -> Users {
        Users {
            allow: Some(self.allowed_pubkeys.clone()),
            deny: Some(self.denied_pubkeys.clone()),
        }
    }

    fn pubkeys_from_nostr(
        &self,
        event: nostr_sdk::event::Event,
    ) -> Result<HashSet<XOnlyPublicKey>> {
        let mut pubkeys = HashSet::new();

        if !event.content.is_empty() {
            if let Ok(content) = decrypt(
                &self.key.secret_key().unwrap(),
                &self.key.public_key(),
                event.content,
            ) {
                let pubkey_tags: Vec<Vec<String>> =
                    serde_json::from_str(&content).unwrap_or_default();

                let pubs: HashSet<XOnlyPublicKey> = pubkey_tags
                    .iter()
                    .filter_map(|i| i.get(1))
                    .flat_map(|str_val| XOnlyPublicKey::from_str(str_val))
                    .collect();

                pubkeys = pubs;
            }
        }

        let tag_pubkeys: HashSet<XOnlyPublicKey> = event
            .tags
            .iter()
            .flat_map(|x| match x {
                Tag::PubKey(p, _) => Some(*p),
                _ => None,
            })
            .collect();

        pubkeys.extend(tag_pubkeys);

        Ok(pubkeys)
    }

    pub async fn update_people(&mut self, event: Event) -> Result<()> {
        let mut encrypted_pubs = HashSet::new();

        if !event.content.is_empty() {
            if let Ok(content) = decrypt(
                &self.key.secret_key().unwrap(),
                &self.key.public_key(),
                event.content,
            ) {
                let pubkey_tags: Vec<Vec<String>> =
                    serde_json::from_str(&content).unwrap_or_default();

                let pubs: HashSet<XOnlyPublicKey> = pubkey_tags
                    .iter()
                    .filter_map(|i| i.get(1))
                    .flat_map(|str_val| XOnlyPublicKey::from_str(str_val))
                    .collect();

                encrypted_pubs = pubs;
            }
        }

        if let Some(t) = event.tags.get(0) {
            if t.values.get(0).eq(&Some(&"d".to_string())) {
                if t.values.get(1).eq(&Some(&"allow".to_string())) {
                    let mut allowed = pubkey_from_tags(event.tags)?;

                    allowed.extend(encrypted_pubs);
                    self.allowed_pubkeys = allowed;
                } else if t.values.get(1).eq(&Some(&"deny".to_string())) {
                    let mut denied = pubkey_from_tags(event.tags)?;

                    denied.extend(encrypted_pubs);
                    self.denied_pubkeys = denied;
                }
            }
        }

        log::debug!("{:?}", self.allowed_pubkeys);

        Ok(())
    }

    pub async fn get_user_status(&self, pubkey: XOnlyPublicKey) -> UserStatus {
        log::debug!("{:?}", pubkey);
        if self.allowed_pubkeys.contains(&pubkey) {
            return UserStatus::Allowed;
        } else if self.denied_pubkeys.contains(&pubkey) {
            return UserStatus::Denied;
        }

        UserStatus::Unknown
    }
}

fn pubkey_from_tags(tags: Vec<TagEntry>) -> Result<HashSet<XOnlyPublicKey>> {
    let mut pubkeys = HashSet::new();
    for p in tags.iter().skip(1) {
        let v = &p.values;
        if let Some(pubkey) = v.get(1) {
            if let Ok(p) = XOnlyPublicKey::from_str(pubkey) {
                pubkeys.insert(p);
            }
        }
    }

    Ok(pubkeys)
}

/*

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
*/
