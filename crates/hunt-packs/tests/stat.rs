mod common;
#[path = "common/sample.rs"]
mod sample;
#[path = "common/stub.rs"]
mod stub;


use common::types::TestResult;
use hunt_packs::run::{HuntOutcome, PackRefusal, RunError};
use hunt_packs::stat_model::{
    bound_id, finding_of, invalid_field, kind_name, merge_stat_packs, parameter_ok, stat_pack, stat_pack_id, validate_stat_hunts, StatHunt,
    Statistic, BOUND_SUFFIX, MAX_ENTITIES_CEILING, MAX_STAT_HUNTS, MAX_STAT_ID_CHARS, MAX_STAT_ROWS, PPM_CEILING,
};
use hunt_packs::stat_run::{
    count_matches, execute_stat_timed, outcome_of, parse_line, parse_rows, read_rows, rows_statement, run_stat, timestamps_by_entity,
    MAX_FIELD_CHARS, MAX_LINE_BYTES,
};
use metric_alerts::fetch::agent_for;
use sample::{pack, param, settings, NOW, PASSWORD};
use std::io::{self, Read};
use std::net::TcpListener;
use std::time::Duration;
use stub::{reply, serve, CLEAN_NAMES};


const MAX_ROWS: u32 = 10;


const LONG: Duration = Duration::from_secs(60);


const OK: &str = "200 OK";


const REGULAR_EVENTS: i64 = 12;


const STEP: i64 = 60;


const HALF_WIDTH: usize = 2;


const OVER_FIELD: usize = 300;


const HEAD: i64 = 1_000;


const JITTER: [i64; 9] = [0, 7, 15, 160, 161, 400, 405, 900, 1_300];


const BEACON_ROWS: u32 = 30;


const HOSTILE_BODIES: usize = 6;


const SLACK_BYTES: u64 = 8_192;


const FOUR_MATCHES: u64 = 4;


const CUT_ROWS: u32 = 3;


fn rarity() -> StatHunt {
    StatHunt {
        id: "rare-process".to_owned(),
        statistic: Statistic::Rarity { max_entities: 1 },
        query: sample::QUERY.to_owned(),
        schedule_seconds: sample::WINDOW,
        window_seconds: sample::WINDOW,
        cost: pack().cost,
        max_rows: MAX_ROWS,
        max_matches: 0,
    }
}


fn beacon() -> StatHunt {
    StatHunt {
        id: "beacon".to_owned(),
        statistic: Statistic::Beaconing {
            min_regularity_ppm: PPM_CEILING - 1,
        },
        ..rarity()
    }
}


fn rows(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(entity, key)| ((*entity).to_owned(), (*key).to_owned())).collect()
}


fn regular(entity: &str, events: i64, step: i64) -> Vec<(String, String)> {
    (0..events).map(|index| (entity.to_owned(), (HEAD + index * step).to_string())).collect()
}


struct Endless {
    served: u64,
}


impl Read for Endless {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        buffer.fill(b'a');
        self.served += buffer.len() as u64;
        Ok(buffer.len())
    }
}


struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("broken"))
    }
}


fn run_against(hunt: &StatHunt, body: Vec<u8>) -> Result<(Result<HuntOutcome, RunError>, String), Box<dyn std::error::Error>> {
    let bound = TcpListener::bind("127.0.0.1:0")?;
    let port = bound.local_addr()?.port();
    let server = reply(bound, OK, "", body);
    let config = settings(port);
    let agent = agent_for(&config)?;
    let outcome = run_stat(&agent, &config, PASSWORD, hunt, "acme", NOW, LONG);
    let seen = server.join().map_err(|_| "server thread")??;
    Ok((outcome, seen))
}


#[test]
fn rarity_counts_keys_seen_on_few_entities_and_stores_a_finding_over_the_baseline() -> TestResult {
    let body = b"h1\tbash\nh2\tbash\nh1\twinword\nh3\twinword\nh2\tmimikatz\n".to_vec();
    let (outcome, seen) = run_against(&rarity(), body)?;
    assert_eq!(
        outcome?,
        HuntOutcome {
            matches: 1,
            finding: true,
            bound: None
        }
    );
    assert!(seen.contains("SELECT * FROM ("), "{seen}");
    assert!(
        seen.contains(") LIMIT 11 SETTINGS max_execution_time = 10, max_rows_to_read = 1000, max_bytes_to_read = 1000000, max_result_rows = 11,"),
        "{seen}"
    );
    assert_eq!(param(&seen, "param_tenant")?, "acme");
    let quiet = StatHunt { max_matches: 1, ..rarity() };
    let (none, _) = run_against(&quiet, b"h1\tbash\nh2\tbash\nh2\trare\n".to_vec())?;
    assert_eq!(
        none?,
        HuntOutcome {
            matches: 1,
            finding: false,
            bound: None
        }
    );
    Ok(())
}


#[test]
fn beaconing_counts_the_entities_with_a_regular_rhythm_only() -> TestResult {
    let mut lines = regular("steady", REGULAR_EVENTS, STEP);
    lines.extend(JITTER.iter().map(|offset| ("jitter".to_owned(), (HEAD + offset).to_string())));
    let body: String = lines.iter().map(|(entity, seconds)| format!("{entity}\t{seconds}\n")).collect();
    let hunt = StatHunt {
        max_rows: BEACON_ROWS,
        ..beacon()
    };
    let (outcome, _) = run_against(&hunt, body.into_bytes())?;
    assert_eq!(
        outcome?,
        HuntOutcome {
            matches: 1,
            finding: true,
            bound: None
        }
    );
    Ok(())
}


#[test]
fn a_reply_over_the_row_bound_is_a_named_finding_never_an_empty_result() -> TestResult {
    let body: String = (0..=MAX_ROWS).map(|index| format!("h{index}\tkey\n")).collect();
    let (outcome, _) = run_against(&rarity(), body.into_bytes())?;
    assert_eq!(
        outcome?,
        HuntOutcome {
            matches: u64::from(MAX_ROWS) + 1,
            finding: true,
            bound: Some(u64::from(MAX_ROWS))
        }
    );
    let one_below: String = (0..MAX_ROWS).map(|index| format!("h{index}\tkey\n")).collect();
    let (within, _) = run_against(&rarity(), one_below.into_bytes())?;
    assert_eq!(within?.bound, None);
    Ok(())
}


#[test]
fn the_bound_outcome_is_stored_under_its_own_id_with_the_bound_as_baseline() -> TestResult {
    let hunt = rarity();
    let stat = stat_pack(&hunt);
    assert_eq!(stat.id, "rarity.rare-process");
    assert_eq!(bound_id(&stat.id), format!("rarity.rare-process{BOUND_SUFFIX}"));
    let over = outcome_of(&hunt, None)?;
    assert_eq!(
        finding_of(&stat, &over),
        ("rarity.rare-process.bound".to_owned(), u64::from(MAX_ROWS) + 1, u64::from(MAX_ROWS))
    );
    let normal = HuntOutcome {
        matches: FOUR_MATCHES,
        finding: true,
        bound: None,
    };
    assert_eq!(finding_of(&stat, &normal), ("rarity.rare-process".to_owned(), FOUR_MATCHES, 0));
    Ok(())
}


#[test]
fn the_reader_never_buffers_more_than_the_row_budget() -> TestResult {
    let mut endless = Endless { served: 0 };
    let outcome = read_rows(&mut endless, MAX_ROWS)?;
    assert!(outcome.is_none());
    assert!(
        endless.served <= (u64::from(MAX_ROWS) + 1) * MAX_LINE_BYTES + 1 + SLACK_BYTES,
        "{}",
        endless.served
    );
    assert!(matches!(read_rows(&mut Broken, MAX_ROWS), Err(RunError::Body(_))));
    assert_eq!(read_rows(&mut &b""[..], MAX_ROWS)?, Some(Vec::new()));
    Ok(())
}


#[test]
fn a_line_that_is_not_a_row_refuses_the_whole_reply() -> TestResult {
    let hostile: [&[u8]; HOSTILE_BODIES] = [
        b"Code: 159. DB::Exception: Timeout\n",
        b"{\"exception\": \"Code: 159\"}\n",
        b"a\tb\nno newline at the end",
        b"a\tb\tc\n",
        b"\xff\xfe\tb\n",
        b"a\tb\n\nc\td\n",
    ];
    hostile.iter().for_each(|body| {
        assert!(matches!(parse_rows(body), Err(RunError::BadRows)), "{body:?}");
        assert!(matches!(read_rows(&mut &body[..], MAX_ROWS), Err(RunError::BadRows)), "{body:?}");
    });
    assert!(parse_line("only").is_err());
    assert_eq!(parse_rows(b"a\tb\n")?, rows(&[("a", "b")]));
    Ok(())
}


#[test]
fn an_over_long_name_is_cut_and_still_groups_with_itself() -> TestResult {
    let long = "x".repeat(OVER_FIELD);
    let (entity, key) = parse_line(&format!("{long}\t{long}y"))?;
    assert_eq!((entity.chars().count(), key.chars().count()), (MAX_FIELD_CHARS, MAX_FIELD_CHARS));
    let parsed = parse_rows(format!("{long}a\t{long}b\n{long}c\t{long}d\n").as_bytes())?;
    assert_eq!(count_matches(&rarity(), &parsed)?, 1);
    Ok(())
}


#[test]
fn the_statistics_refuse_what_cannot_be_scored_with_a_fixed_error() -> TestResult {
    let extreme = rows(&[("p", &i64::MIN.to_string()), ("p", &i64::MAX.to_string())]);
    let overflow = count_matches(&beacon(), &extreme).err().ok_or("accepted")?;
    assert!(matches!(overflow, RunError::Stats(_)));
    assert_eq!(overflow.to_string(), "the statistics refused the rows");
    let too_many = rows(&[("a", "k"), ("b", "k")]);
    let small = StatHunt { max_rows: 1, ..rarity() };
    assert!(matches!(count_matches(&small, &too_many), Err(RunError::Stats(_))));
    assert!(matches!(count_matches(&beacon(), &rows(&[("p", "soon")])), Err(RunError::BadRows)));
    assert!(timestamps_by_entity(&rows(&[("p", "1"), ("p", "2"), ("q", "3")]))?.len() == HALF_WIDTH);
    Ok(())
}


#[test]
fn a_profile_that_changed_a_setting_refuses_a_statistical_hunt_before_its_query() -> TestResult {
    let bound = TcpListener::bind("127.0.0.1:0")?;
    let port = bound.local_addr()?.port();
    let listener = bound.try_clone()?;
    let server = std::thread::spawn(move || -> io::Result<String> {
        let (stream, _) = listener.accept()?;
        serve(stream, OK, "", format!("{}\nmax_block_size\n", CLEAN_NAMES.join("\n")).as_bytes())
    });
    let config = settings(port);
    let agent = agent_for(&config)?;
    let outcome = execute_stat_timed(&agent, &config, PASSWORD, &rarity(), "acme", NOW, &|| LONG);
    let seen = server.join().map_err(|_| "server thread")??;
    assert!(matches!(outcome, Err(RunError::ReaderProfileChanged(1))), "{outcome:?}");
    assert!(seen.contains("`system`.`settings`"), "{seen}");
    bound.set_nonblocking(true)?;
    assert_eq!(bound.accept().err().map(|error| error.kind()), Some(io::ErrorKind::WouldBlock));
    Ok(())
}


#[test]
fn a_cost_refusal_and_a_pack_that_names_settings_are_the_packs_own_errors() -> TestResult {
    let bound = TcpListener::bind("127.0.0.1:0")?;
    let port = bound.local_addr()?.port();
    let server = reply(
        bound,
        "500 Internal Server Error",
        "X-ClickHouse-Exception-Code: 158\r\n",
        b"Code: 158".to_vec(),
    );
    let config = settings(port);
    let agent = agent_for(&config)?;
    let outcome = run_stat(&agent, &config, PASSWORD, &rarity(), "acme", NOW, LONG);
    server.join().map_err(|_| "server thread")??;
    assert!(matches!(outcome, Err(RunError::PackRefused(PackRefusal::Cost))), "{outcome:?}");
    let lifting = StatHunt {
        query: format!("{} SETTINGS max_rows_to_read = 0", sample::QUERY.trim_end_matches(';')),
        ..rarity()
    };
    let refused = execute_stat_timed(&agent, &config, PASSWORD, &lifting, "acme", NOW, &|| LONG);
    assert!(matches!(refused, Err(RunError::PackSettings)));
    let wrong_tenant = execute_stat_timed(&agent, &config, PASSWORD, &rarity(), "-x", NOW, &|| LONG);
    assert!(matches!(wrong_tenant, Err(RunError::Tenant(_))));
    Ok(())
}


#[test]
fn the_statement_wraps_the_query_and_pins_the_row_cap() -> TestResult {
    let text = rows_statement("SELECT 1 -- comment ;", &[("max_rows_to_read", "5".to_owned())], CUT_ROWS);
    assert!(
        text.starts_with("SELECT * FROM (\nSELECT 1 -- comment\n) LIMIT 4 SETTINGS max_rows_to_read = 5, max_result_rows = 4,"),
        "{text}"
    );
    assert!(text.ends_with(" FORMAT TabSeparated"), "{text}");
    Ok(())
}


#[test]
fn every_field_of_a_statistical_hunt_is_checked_and_the_first_failure_is_named() -> TestResult {
    assert_eq!(invalid_field(&rarity()), None);
    assert_eq!(invalid_field(&beacon()), None);
    let cases: Vec<(StatHunt, &str)> = vec![
        (
            StatHunt {
                id: "Bad Id".to_owned(),
                ..rarity()
            },
            "id",
        ),
        (
            StatHunt {
                id: "x".repeat(MAX_STAT_ID_CHARS + 1),
                ..rarity()
            },
            "id",
        ),
        (
            StatHunt {
                statistic: Statistic::Rarity { max_entities: 0 },
                ..rarity()
            },
            "statistic",
        ),
        (
            StatHunt {
                statistic: Statistic::Rarity {
                    max_entities: MAX_ENTITIES_CEILING + 1,
                },
                ..rarity()
            },
            "statistic",
        ),
        (
            StatHunt {
                statistic: Statistic::Beaconing { min_regularity_ppm: 0 },
                ..rarity()
            },
            "statistic",
        ),
        (
            StatHunt {
                statistic: Statistic::Beaconing {
                    min_regularity_ppm: PPM_CEILING + 1,
                },
                ..rarity()
            },
            "statistic",
        ),
        (
            StatHunt {
                query: "SELECT 1".to_owned(),
                ..rarity()
            },
            "query",
        ),
        (
            StatHunt {
                query: String::new(),
                ..rarity()
            },
            "query",
        ),
        (
            StatHunt {
                schedule_seconds: 1,
                ..rarity()
            },
            "schedule_seconds",
        ),
        (
            StatHunt {
                window_seconds: 1,
                ..rarity()
            },
            "window_seconds",
        ),
        (
            StatHunt {
                window_seconds: sample::WINDOW - 1,
                ..rarity()
            },
            "window_seconds",
        ),
        (StatHunt { max_rows: 0, ..rarity() }, "max_rows"),
        (
            StatHunt {
                max_rows: MAX_STAT_ROWS + 1,
                ..rarity()
            },
            "max_rows",
        ),
        (
            StatHunt {
                max_matches: u64::MAX,
                ..rarity()
            },
            "max_matches",
        ),
    ];
    cases
        .iter()
        .for_each(|(hunt, field)| assert_eq!(invalid_field(hunt), Some(*field), "{hunt:?}"));
    let mut no_bytes = rarity();
    no_bytes.cost.max_bytes_read = None;
    assert_eq!(invalid_field(&no_bytes), Some("cost.max_bytes_read"));
    let mut no_rows = rarity();
    no_rows.cost.max_rows = 0;
    assert_eq!(invalid_field(&no_rows), Some("cost.max_rows"));
    let mut no_seconds = rarity();
    no_seconds.cost.max_seconds = 0;
    assert_eq!(invalid_field(&no_seconds), Some("cost.max_seconds"));
    assert!(parameter_ok(&Statistic::Rarity { max_entities: 1 }));
    assert_eq!(kind_name(&beacon().statistic), "beaconing");
    assert_eq!(stat_pack_id(&beacon()), "beaconing.beacon");
    Ok(())
}


#[test]
fn a_list_is_valid_when_every_hunt_is_and_ids_are_unique_and_few() -> TestResult {
    assert_eq!(validate_stat_hunts(&[rarity(), beacon()]), Ok(()));
    assert_eq!(validate_stat_hunts(&[rarity(), rarity()]), Err("id"));
    assert_eq!(validate_stat_hunts(&[StatHunt { max_rows: 0, ..rarity() }]), Err("max_rows"));
    let same_id_other_kind = StatHunt { id: rarity().id, ..beacon() };
    assert_eq!(validate_stat_hunts(&[rarity(), same_id_other_kind]), Ok(()));
    let many: Vec<StatHunt> = (0..=MAX_STAT_HUNTS)
        .map(|index| StatHunt {
            id: format!("h{index}"),
            ..rarity()
        })
        .collect();
    assert_eq!(validate_stat_hunts(&many), Err("stat_hunts"));
    Ok(())
}


#[test]
fn a_hunt_whose_scheduler_id_a_file_pack_holds_is_dropped_and_counted() -> TestResult {
    let mut taken = pack();
    taken.id = stat_pack_id(&rarity());
    let (merged, clashes) = merge_stat_packs(vec![taken.clone(), pack()], &[rarity(), beacon()]);
    assert_eq!(clashes, 1);
    assert_eq!(merged.len(), usize::try_from(CUT_ROWS)?);
    assert_eq!(merged.first(), Some(&taken));
    assert_eq!(merged.iter().filter(|item| item.id == "beaconing.beacon").count(), 1);
    Ok(())
}


#[test]
fn a_reply_that_is_not_rows_and_rows_that_cannot_be_scored_fail_the_run_loudly() -> TestResult {
    let (exception, _) = run_against(&rarity(), b"Code: 159. DB::Exception: Timeout\n".to_vec())?;
    assert!(matches!(exception, Err(RunError::BadRows)), "{exception:?}");
    let (unscored, _) = run_against(&beacon(), b"pair\tsoon\n".to_vec())?;
    assert!(matches!(unscored, Err(RunError::BadRows)), "{unscored:?}");
    Ok(())
}
