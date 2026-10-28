//! Fill missing library artwork/details without repeating known lookups.
use serde_json::Value;
use swifttunnel_core::roblox_library::{GameEntry, valid_place_id};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Metadata {
    pub universe: String,
    pub root_place: Option<String>,
    pub name: String,
    pub icon: Option<String>,
}

pub(super) fn needed(entry: &GameEntry) -> bool {
    entry.name == format!("Place {}", entry.place_id)
        || entry.icon_url.is_none()
        || entry.universe_id.is_none()
        || entry.root_place_id.is_none()
}

pub(super) async fn resolve<F, Fut>(
    entry: &GameEntry,
    mut fetch: F,
) -> Result<Option<Metadata>, String>
where
    F: FnMut(String, usize) -> Fut,
    Fut: std::future::Future<Output = Result<Value, String>>,
{
    let universe = match &entry.universe_id {
        Some(id) => id.clone(),
        None => fetch(
            format!(
                "https://apis.roblox.com/universes/v1/places/{}/universe",
                entry.place_id
            ),
            64 * 1024,
        )
        .await?
        .get("universeId")
        .and_then(Value::as_u64)
        .map(|id| id.to_string())
        .filter(|id| valid_place_id(id))
        .ok_or("Game details are unavailable. Try refreshing your library later.")?,
    };
    let mut result = Metadata {
        universe,
        root_place: entry.root_place_id.clone(),
        name: entry.name.clone(),
        icon: entry.icon_url.clone(),
    };
    if result.root_place.is_none() || result.name == format!("Place {}", entry.place_id) {
        let data = fetch(
            format!(
                "https://games.roblox.com/v1/games?universeIds={}",
                result.universe
            ),
            64 * 1024,
        )
        .await?;
        let game = data
            .get("data")
            .and_then(|data| data.get(0))
            .ok_or("Game details are unavailable. Try refreshing your library later.")?;
        if let Some(root) = game
            .get("rootPlaceId")
            .and_then(Value::as_u64)
            .map(|id| id.to_string())
            .filter(|id| valid_place_id(id))
        {
            result.root_place = Some(root);
        }
        result.name = game
            .get("name")
            .and_then(Value::as_str)
            .ok_or("Game details are unavailable. Try refreshing your library later.")?
            .into();
    }
    if result.icon.is_none() {
        // A missing/pending thumbnail must not discard successfully read details.
        if let Ok(data) = fetch(
            format!("https://thumbnails.roblox.com/v1/games/icons?universeIds={}&size=256x256&format=Png&isCircular=false", result.universe),
            32 * 1024,
        ).await {
            result.icon = data.get("data").and_then(|data| data.get(0))
                .and_then(|image| image.get("imageUrl")).and_then(Value::as_str).map(str::to_owned);
        }
    }
    if entry.universe_id.as_ref() == Some(&result.universe)
        && entry.root_place_id == result.root_place
        && entry.name == result.name
        && entry.icon_url == result.icon
    {
        Ok(None)
    } else {
        Ok(Some(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use swifttunnel_core::roblox_library::{GamePreferences, RobloxClient};

    fn known() -> GameEntry {
        GameEntry {
            place_id: "1818".into(),
            universe_id: Some("99".into()),
            root_place_id: Some("1818".into()),
            name: "Crossroads".into(),
            job_id: None,
            last_played: None,
            favourite: true,
            favourite_revision: 1,
            preferences_revision: 1,
            client: RobloxClient::Standard,
            preferences: GamePreferences::default(),
            icon_url: Some("https://tr.rbxcdn.com/known.png".into()),
        }
    }

    #[tokio::test]
    async fn missing_artwork_retries_only_the_thumbnail_and_no_change_needs_no_write() {
        let mut entry = known();
        entry.icon_url = None;
        let mut urls = Vec::new();
        let result = resolve(&entry, |url, _| {
            urls.push(url);
            std::future::ready(Err("thumbnail unavailable".into()))
        })
        .await
        .unwrap();
        assert!(result.is_none());
        assert_eq!(urls.len(), 1);
        assert!(urls[0].starts_with("https://thumbnails.roblox.com/"));
        let result = resolve(&entry, |_, _| {
            std::future::ready(Ok(
                json!({"data":[{"imageUrl":"https://tr.rbxcdn.com/new.png"}]}),
            ))
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.name, "Crossroads");
        assert_eq!(result.root_place.as_deref(), Some("1818"));
        assert_eq!(
            result.icon.as_deref(),
            Some("https://tr.rbxcdn.com/new.png")
        );
    }

    #[tokio::test]
    async fn known_universe_and_artwork_survive_a_missing_root_lookup() {
        let mut entry = known();
        entry.root_place_id = None;
        let mut urls = Vec::new();
        let result = resolve(&entry, |url, _| {
            urls.push(url);
            std::future::ready(Ok(
                json!({"data":[{"rootPlaceId":1819,"name":"New title"}]}),
            ))
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(urls, ["https://games.roblox.com/v1/games?universeIds=99"]);
        assert_eq!(result.root_place.as_deref(), Some("1819"));
        assert_eq!(result.icon, entry.icon_url);
    }

    #[tokio::test]
    async fn a_new_game_resolves_details_in_order_and_incomplete_artwork_keeps_them() {
        let mut entry = known();
        entry.universe_id = None;
        entry.root_place_id = None;
        entry.name = "Place 1818".into();
        entry.icon_url = None;
        let mut calls = Vec::new();
        let result = resolve(&entry, |url, limit| {
            calls.push((url.clone(), limit));
            std::future::ready(Ok(if url.starts_with("https://apis.roblox.com/") {
                json!({"universeId":99})
            } else if url.starts_with("https://games.roblox.com/") {
                json!({"data":[{"rootPlaceId":1818,"name":"Crossroads"}]})
            } else {
                json!({"data":[{"state":"Pending"}]})
            }))
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls.iter().map(|(_, limit)| *limit).collect::<Vec<_>>(),
            [65536, 65536, 32768]
        );
        assert_eq!(result.universe, "99");
        assert_eq!(result.name, "Crossroads");
        assert!(result.icon.is_none());
    }

    #[tokio::test]
    async fn complete_metadata_makes_no_request_and_bad_identity_does_not_continue() {
        assert!(!needed(&known()));
        assert!(
            resolve(&known(), |_, _| async {
                panic!("complete entry must not fetch")
            })
            .await
            .unwrap()
            .is_none()
        );
        let mut entry = known();
        entry.universe_id = None;
        let mut count = 0;
        assert!(
            resolve(&entry, |_, _| {
                count += 1;
                std::future::ready(Ok(json!({"universeId":0})))
            })
            .await
            .is_err()
        );
        assert_eq!(count, 1);
    }
}
