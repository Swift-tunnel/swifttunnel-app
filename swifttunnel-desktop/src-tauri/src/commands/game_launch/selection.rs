use super::{ServerSearch, matchmaking::ServerDirectory};
use std::time::{Duration, Instant};
use swifttunnel_core::roblox_directory::{Availability, Datacenter};

pub(super) struct Selection {
    pub job: String,
    pub availability: Availability,
    pub search: Option<ServerSearch>,
}

pub(super) async fn select_server(
    directory: &mut impl ServerDirectory,
    place: &str,
    center: &Datacenter,
    requested: Option<String>,
    cached: Option<ServerSearch>,
) -> Result<Selection, String> {
    let cached = cached.filter(|s| {
        s.place_id == place
            && s.center.id == center.id
            && s.fetched.elapsed() < Duration::from_secs(30)
    });
    if let Some(job) = requested {
        // A selected server may have come from page two, or from a search
        // replaced while connecting. Validate its exact ID; page one is not
        // evidence that a different selected server disappeared.
        let availability = if let Some(server) = cached
            .as_ref()
            .and_then(|s| s.servers.iter().find(|s| s.job_id == job))
        {
            server.availability
        } else {
            directory
                .availability(place, &job)
                .await
                .unwrap_or(Availability::Unknown)
        };
        return Ok(Selection {
            job,
            availability,
            search: None,
        });
    }
    let search = match cached {
        Some(search) => search,
        None => ServerSearch {
            place_id: place.into(),
            center: center.clone(),
            servers: directory.page(center.id, None).await?.servers,
            fetched: Instant::now(),
        },
    };
    let server = search
        .servers
        .iter()
        .filter(|s| {
            matches!(
                s.availability,
                Availability::Available | Availability::Unknown
            )
        })
        .min_by_key(|s| {
            (
                s.availability != Availability::Available,
                s.playing.unwrap_or(u32::MAX),
            )
        });
    let Some(server) = server else {
        return Err(if search.servers.is_empty() {
            format!(
                "No {} servers are listed for this game. Try another location or Play normally.",
                center.city
            )
        } else {
            format!(
                "No joinable {} server was found in this search. Refresh, choose another location or Play normally.",
                center.city
            )
        });
    };
    Ok(Selection {
        job: server.job_id.clone(),
        availability: server.availability,
        search: Some(search),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use swifttunnel_core::roblox_directory::{GameServer, ServerPage};

    struct Directory {
        availability: Result<Availability, String>,
        pages: usize,
        lookups: Vec<(String, String)>,
    }
    impl ServerDirectory for Directory {
        async fn page(&mut self, _: u32, _: Option<u32>) -> Result<ServerPage, String> {
            self.pages += 1;
            Ok(ServerPage {
                servers: vec![server("first-page", Availability::Available)],
                next_cursor: None,
                warning: None,
            })
        }
        async fn availability(&mut self, place: &str, job: &str) -> Result<Availability, String> {
            self.lookups.push((place.into(), job.into()));
            self.availability.clone()
        }
    }
    fn server(job: &str, availability: Availability) -> GameServer {
        GameServer {
            job_id: job.into(),
            datacenter_id: 1,
            ip: None,
            first_seen: String::new(),
            playing: Some(1),
            capacity: Some(10),
            availability,
        }
    }
    fn center() -> Datacenter {
        Datacenter {
            id: 1,
            city: "Mumbai".into(),
            country: "IN".into(),
            datacenter_ids: vec![1],
            relay_region: Some("mumbai".into()),
        }
    }
    fn directory(availability: Result<Availability, String>) -> Directory {
        Directory {
            availability,
            pages: 0,
            lookups: vec![],
        }
    }
    fn search(age: u64) -> ServerSearch {
        ServerSearch {
            place_id: "1818".into(),
            center: center(),
            servers: vec![server("later-page", Availability::Available)],
            fetched: Instant::now() - Duration::from_secs(age),
        }
    }

    #[tokio::test]
    async fn expired_or_replaced_searches_check_the_selected_job_without_reloading_page_one() {
        for cached in [
            Some(search(31)),
            None,
            Some(ServerSearch {
                place_id: "9999".into(),
                ..search(0)
            }),
        ] {
            let mut directory = directory(Ok(Availability::Available));
            let selected = select_server(
                &mut directory,
                "1818",
                &center(),
                Some("later-page".into()),
                cached,
            )
            .await
            .unwrap();
            assert_eq!(selected.job, "later-page");
            assert_eq!(selected.availability, Availability::Available);
            assert!(selected.search.is_none());
            assert_eq!(directory.pages, 0);
            assert_eq!(
                directory.lookups,
                vec![("1818".into(), "later-page".into())]
            );
        }
    }

    #[tokio::test]
    async fn a_fresh_later_page_selection_uses_its_known_status_without_another_lookup() {
        let mut directory = directory(Err("unexpected lookup".into()));
        let selected = select_server(
            &mut directory,
            "1818",
            &center(),
            Some("later-page".into()),
            Some(search(0)),
        )
        .await
        .unwrap();
        assert_eq!(selected.availability, Availability::Available);
        assert!(directory.lookups.is_empty());
        assert_eq!(directory.pages, 0);
    }

    #[tokio::test]
    async fn closed_servers_and_failed_checks_never_inherit_old_availability() {
        for answer in [Ok(Availability::Full), Err("directory unavailable".into())] {
            let expected = answer.clone().unwrap_or(Availability::Unknown);
            let mut directory = directory(answer);
            let selected = select_server(
                &mut directory,
                "1818",
                &center(),
                Some("later-page".into()),
                Some(search(31)),
            )
            .await
            .unwrap();
            assert_eq!(selected.availability, expected);
        }
    }

    #[tokio::test]
    async fn a_location_search_without_a_specific_job_still_fetches_current_choices() {
        let mut directory = directory(Err("unexpected lookup".into()));
        let selected = select_server(&mut directory, "1818", &center(), None, Some(search(31)))
            .await
            .unwrap();
        assert_eq!(selected.job, "first-page");
        assert!(selected.search.is_some());
        assert_eq!(directory.pages, 1);
        assert!(directory.lookups.is_empty());
    }
}
