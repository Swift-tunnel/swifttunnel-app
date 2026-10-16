use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
};
use swifttunnel_core::{
    roblox_directory::{self, Availability, Datacenter, GameServer, ServerLookup, ServerPage},
    roblox_launcher::{MatchMode, Matchmaker, qualifies},
};

pub(super) trait ServerDirectory {
    fn page(
        &mut self,
        location: u32,
        cursor: Option<u32>,
    ) -> impl Future<Output = Result<ServerPage, String>> + Send;
    fn availability(
        &mut self,
        place: &str,
        job: &str,
    ) -> impl Future<Output = Result<Availability, String>> + Send;
}
impl ServerDirectory for ServerLookup {
    async fn page(&mut self, location: u32, cursor: Option<u32>) -> Result<ServerPage, String> {
        self.servers(location, cursor).await
    }
    async fn availability(&mut self, place: &str, job: &str) -> Result<Availability, String> {
        roblox_directory::availability(place, job).await
    }
}

pub(super) struct Candidate {
    pub center: Datacenter,
    pub servers: Vec<GameServer>,
    pub job: String,
}
struct LocationSearch {
    order: u32,
    score: u32,
    center: Datacenter,
    cursor: Option<u32>,
    seen_cursors: HashSet<u32>,
    rows: Vec<GameServer>,
}

/// Give each location a first page before returning for further pages. Closest
/// then searches only nearer locations before accepting a farther candidate;
/// Fewer Players keeps comparing all locations in rounds.
/// Both use one total row budget, a request cap and the caller's deadline.
pub(super) async fn find_server(
    lookup: &mut impl ServerDirectory,
    centers: Vec<(u32, Datacenter)>,
    config: &Matchmaker,
    deadline: tokio::time::Instant,
) -> Result<Candidate, String> {
    let mut queue: VecDeque<_> = centers
        .into_iter()
        .take(4)
        .enumerate()
        .map(|(order, (score, center))| LocationSearch {
            order: order as u32,
            score,
            center,
            cursor: None,
            seen_cursors: HashSet::new(),
            rows: Vec::new(),
        })
        .collect();
    let mut remaining = config.search_limit.min(200) as usize;
    let mut requests = 0;
    let mut candidates = HashMap::new();
    let mut last_error = None;
    let mut received_page = false;
    while remaining > 0 && requests < 16 && tokio::time::Instant::now() < deadline {
        let Some(mut location) = queue.pop_front() else {
            break;
        };
        requests += 1;
        let page = match tokio::time::timeout_at(
            deadline,
            lookup.page(location.center.id, location.cursor),
        )
        .await
        {
            Ok(Ok(page)) => page,
            Ok(Err(error)) => {
                last_error = Some(error);
                continue;
            }
            Err(_) => {
                last_error = Some("The server search took too long. Try again.".into());
                break;
            }
        };
        received_page = true;
        let count = page.servers.len().min(50).min(remaining);
        // Empty or duplicate pages must still spend budget rather than
        // allowing a faulty directory to keep a search running indefinitely.
        remaining = remaining.saturating_sub(count.max(1));
        for server in page.servers.into_iter().take(count) {
            if let Some(old) = location.rows.iter_mut().find(|s| s.job_id == server.job_id) {
                *old = server;
            } else {
                location.rows.push(server);
            }
        }
        if let Some(server) = location
            .rows
            .iter()
            .filter(|s| qualifies(s, config.minimum_free_slots))
            .min_by_key(|s| s.playing.unwrap_or(u32::MAX))
        {
            let population = server.playing.unwrap_or(u32::MAX);
            let rank = match config.mode {
                MatchMode::Closest => (location.order, population),
                MatchMode::FewerPlayers => (population, location.score),
            };
            let candidate = Candidate {
                center: location.center.clone(),
                job: server.job_id.clone(),
                servers: location.rows.clone(),
            };
            candidates.insert(location.center.id, (rank, candidate));
        } else {
            candidates.remove(&location.center.id);
        }
        if let Some(cursor) = page.next_cursor
            && location.seen_cursors.insert(cursor)
        {
            location.cursor = Some(cursor);
            queue.push_back(location);
        }
        if config.mode == MatchMode::Closest
            && let Some(best_order) = candidates.values().map(|(rank, _)| rank.0).min()
        {
            // A nearer location may have another page. Retain that work,
            // but don't spend the remaining budget on farther locations.
            queue.retain(|location| location.order < best_order);
        }
    }
    if let Some((_, candidate)) = candidates.into_values().min_by_key(|(rank, _)| *rank) {
        return Ok(candidate);
    }
    if tokio::time::Instant::now() >= deadline {
        return Err("The server search took too long. Try again.".into());
    }
    if !received_page && let Some(error) = last_error {
        return Err(error);
    }
    Err("No server matched your Matchmaker settings. Try another location or Play normally.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use swifttunnel_core::roblox_directory::Availability;

    struct Pages {
        responses: VecDeque<(u32, Option<u32>, ServerPage)>,
        delay: Duration,
        calls: usize,
    }
    impl ServerDirectory for Pages {
        async fn page(&mut self, location: u32, cursor: Option<u32>) -> Result<ServerPage, String> {
            self.calls += 1;
            tokio::time::sleep(self.delay).await;
            let (expected_location, expected_cursor, page) = self
                .responses
                .pop_front()
                .expect("unexpected directory request");
            assert_eq!((location, cursor), (expected_location, expected_cursor));
            Ok(page)
        }
        async fn availability(&mut self, _: &str, _: &str) -> Result<Availability, String> {
            panic!("automatic search must not invent slots from a separate server lookup");
        }
    }
    fn center(id: u32) -> (u32, Datacenter) {
        (
            id * 10,
            Datacenter {
                id,
                city: id.to_string(),
                country: "IN".into(),
                datacenter_ids: vec![id],
                relay_region: Some("mumbai".into()),
            },
        )
    }
    fn server(id: u32, playing: u32) -> GameServer {
        GameServer {
            job_id: id.to_string(),
            datacenter_id: 1,
            ip: None,
            first_seen: String::new(),
            playing: Some(playing),
            capacity: Some(10),
            availability: if playing < 10 {
                Availability::Available
            } else {
                Availability::Full
            },
        }
    }
    fn page(rows: Vec<GameServer>, next: Option<u32>) -> ServerPage {
        ServerPage {
            servers: rows,
            next_cursor: next,
            warning: None,
        }
    }
    fn pages(responses: Vec<(u32, Option<u32>, ServerPage)>) -> Pages {
        Pages {
            responses: responses.into(),
            delay: Duration::ZERO,
            calls: 0,
        }
    }
    fn deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(2)
    }

    #[tokio::test]
    async fn closest_reads_the_next_page_before_abandoning_the_nearer_location() {
        let mut pages = pages(vec![
            (
                1,
                None,
                page((1..=50).map(|id| server(id, 10)).collect(), Some(50)),
            ),
            (2, None, page(vec![server(60, 1)], None)),
            (1, Some(50), page(vec![server(51, 3)], None)),
        ]);
        let result = find_server(
            &mut pages,
            vec![center(1), center(2)],
            &Matchmaker {
                search_limit: 100,
                ..Default::default()
            },
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(result.center.id, 1);
        assert_eq!(result.job, "51");
        assert_eq!(result.servers.len(), 51);
        assert_eq!(pages.calls, 3);
    }

    #[tokio::test]
    async fn a_busy_nearest_location_cannot_spend_the_whole_budget_before_checking_a_fallback() {
        let mut pages = pages(vec![
            (
                1,
                None,
                page((1..=50).map(|id| server(id, 10)).collect(), Some(50)),
            ),
            (2, None, page(vec![server(100, 1)], None)),
            (
                1,
                Some(50),
                page((51..=100).map(|id| server(id, 10)).collect(), Some(100)),
            ),
        ]);
        let result = find_server(
            &mut pages,
            vec![center(1), center(2)],
            &Matchmaker {
                search_limit: 60,
                ..Default::default()
            },
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(result.center.id, 2);
        assert_eq!(result.job, "100");
        assert_eq!(pages.calls, 3);
    }

    #[tokio::test]
    async fn fewer_players_checks_each_location_then_later_pages_within_one_budget() {
        let mut pages = pages(vec![
            (1, None, page(vec![server(1, 8)], Some(1))),
            (2, None, page(vec![server(2, 4)], None)),
            (1, Some(1), page(vec![server(3, 1)], None)),
        ]);
        let result = find_server(
            &mut pages,
            vec![center(1), center(2)],
            &Matchmaker {
                mode: MatchMode::FewerPlayers,
                ..Default::default()
            },
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(result.center.id, 1);
        assert_eq!(result.job, "3");
        assert_eq!(result.servers.len(), 2);
    }

    #[tokio::test]
    async fn a_later_full_record_does_not_leave_an_old_candidate_marked_available() {
        let mut pages = pages(vec![
            (1, None, page(vec![server(1, 1)], Some(1))),
            (2, None, page(vec![server(2, 2)], None)),
            (1, Some(1), page(vec![server(1, 10)], None)),
        ]);
        let result = find_server(
            &mut pages,
            vec![center(1), center(2)],
            &Matchmaker {
                mode: MatchMode::FewerPlayers,
                ..Default::default()
            },
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(result.center.id, 2);
        assert_eq!(result.job, "2");
    }

    #[tokio::test]
    async fn empty_advancing_pages_have_a_request_cap_even_with_a_large_row_budget() {
        let mut pages = pages(
            (0..100)
                .map(|i| (1, (i > 0).then_some(i), page(vec![], Some(i + 1))))
                .collect(),
        );
        assert!(
            find_server(
                &mut pages,
                vec![center(1)],
                &Matchmaker {
                    search_limit: 200,
                    ..Default::default()
                },
                deadline()
            )
            .await
            .is_err()
        );
        assert!(pages.calls <= 16);
        assert!(pages.calls > 1);
    }

    #[tokio::test]
    async fn unknown_slots_and_cyclic_cursors_never_make_a_server_eligible_or_loop() {
        let mut unknown = server(1, 0);
        unknown.availability = Availability::Unknown;
        let mut pages = pages(vec![
            (1, None, page(vec![unknown], Some(1))),
            (1, Some(1), page(vec![server(2, 9)], Some(2))),
            (1, Some(2), page(vec![], Some(1))),
        ]);
        assert!(
            find_server(
                &mut pages,
                vec![center(1)],
                &Matchmaker {
                    minimum_free_slots: 2,
                    ..Default::default()
                },
                deadline()
            )
            .await
            .is_err()
        );
        assert_eq!(pages.calls, 3);
    }

    #[tokio::test]
    async fn a_server_outside_the_total_row_limit_does_not_expand_the_search() {
        let mut rows = (1..=10).map(|id| server(id, 10)).collect::<Vec<_>>();
        rows.push(server(11, 0));
        let mut pages = pages(vec![(1, None, page(rows, Some(1)))]);
        assert!(
            find_server(
                &mut pages,
                vec![center(1), center(2)],
                &Matchmaker {
                    search_limit: 10,
                    ..Default::default()
                },
                deadline()
            )
            .await
            .is_err()
        );
        assert_eq!(pages.calls, 1);
    }

    #[tokio::test]
    async fn the_deadline_cancels_a_stuck_page_and_does_not_start_another() {
        let mut pages = pages(vec![]);
        pages.delay = Duration::from_secs(1);
        let result = find_server(
            &mut pages,
            vec![center(1), center(2)],
            &Matchmaker::default(),
            tokio::time::Instant::now() + Duration::from_millis(5),
        )
        .await;
        assert!(result.err().unwrap().contains("too long"));
        assert_eq!(pages.calls, 1);
    }
}
