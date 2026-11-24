use mail_parser::{Header, HeaderName, HeaderValue};
use phishing_report::limits::{Limits, MAX_HEADER_REGION_BYTES};
use phishing_report::model::{ReporterPolicy, Triage};
use phishing_report::region::lines_ambiguous;
use phishing_report::triage::{triage, triage_with};


const PART_LIMIT: usize = 2;


const GAP: u32 = 2;


const REASON: &str = "header_region_ambiguous";


const TOP: &[u8] = b"From: a@x.test\r\nMIME-Version: 1.0\r\n";


const MIXED: &[u8] = b"Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n";


const END: &[u8] = b"--b1--\r\n";


const PLAIN: &[u8] = b"--b1\r\nContent-Type: text/plain\r\n\r\nhello\r\n";


const LONG_LINE_BYTES: usize = 4000;


const LINE_MARGIN: usize = 100;


const FIRST: u32 = 100;


const LINE_LENGTH: u32 = 8;


fn run(raw: &[u8]) -> Result<Triage, Box<dyn std::error::Error>> {
    Ok(triage(raw, &["mx.example.org".to_owned()], &ReporterPolicy::default())?)
}


fn joined(pieces: &[&[u8]]) -> Vec<u8> {
    pieces.concat()
}


fn mixed(body: &[&[u8]]) -> Vec<u8> {
    let mut raw = joined(&[TOP, MIXED]);
    body.iter().for_each(|piece| raw.extend_from_slice(piece));
    raw
}


fn is_flagged(raw: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    let record = run(raw)?;
    let named = record.uncertain_reasons.iter().any(|reason| reason == REASON);
    assert_eq!(named, record.counts.header_region_ambiguous > 0);
    Ok(named)
}


fn all_flagged(cases: &[(&str, Vec<u8>)]) -> Result<(), Box<dyn std::error::Error>> {
    cases.iter().try_for_each(|(name, raw)| {
        assert!(is_flagged(raw)?, "{name} must be flagged");
        Ok(())
    })
}


fn none_flagged(cases: &[(&str, Vec<u8>)]) -> Result<(), Box<dyn std::error::Error>> {
    cases.iter().try_for_each(|(name, raw)| {
        assert!(!is_flagged(raw)?, "{name} must not be flagged");
        Ok(())
    })
}


fn long_header_mail(lines: usize) -> Vec<u8> {
    let mut raw = b"From: a@x.test\r\n".to_vec();
    (0..lines).for_each(|_| {
        raw.extend_from_slice(b"X-A: ");
        raw.extend_from_slice(&[b'a'; LONG_LINE_BYTES]);
        raw.extend_from_slice(b"\r\n");
    });
    raw.extend_from_slice(b"\r\nhello\r\n");
    raw
}


fn header(offset: u32) -> Header<'static> {
    Header {
        name: HeaderName::Other("X-A".into()),
        value: HeaderValue::Empty,
        offset_field: offset,
        offset_start: offset,
        offset_end: offset,
    }
}


#[test]
fn ordinary_mail_is_not_flagged() -> Result<(), Box<dyn std::error::Error>> {
    none_flagged(&[
        ("crlf", mixed(&[PLAIN, END])),
        ("lf", mixed(&[PLAIN, END]).iter().copied().filter(|byte| *byte != b'\r').collect()),
        ("no final newline", mixed(&[PLAIN, b"--b1--"])),
        ("blanks after the delimiters", mixed(&[b"--b1 \t\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b1-- \t\r\nepilogue\r\n"])),
        ("blanks at the very end", mixed(&[PLAIN, b"--b1--  "])),
        ("preamble", mixed(&[b"preamble\r\n", PLAIN, END])),
        ("no preamble", joined(&[TOP, b"Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n", PLAIN, END])),
        ("two children", mixed(&[PLAIN, PLAIN, END])),
        ("epilogue", mixed(&[PLAIN, b"--b1--\r\n\r\nepilogue\r\n"])),
        ("fold", b"From: a@x.test\r\nSubject: one\r\n two\r\n\tthree\r\nContent-Type: text/plain\r\n\r\nhi\r\n".to_vec()),
        ("mbox line", b"From a@x.test Mon Jan  1 10:00:00 2003\nFrom: a@x.test\n\nhi\n".to_vec()),
        (
            "nested alternative",
            mixed(&[
                b"--b1\r\nContent-Type: multipart/alternative; boundary=\"b2\"\r\n\r\n--b2\r\nContent-Type: text/plain\r\n\r\na\r\n",
                b"--b2\r\nContent-Type: text/html\r\n\r\nb\r\n--b2--\r\n--b1\r\nContent-Type: application/pdf\r\n\r\nxx\r\n--b1--\r\n",
            ]),
        ),
        (
            "nested last",
            mixed(&[
                PLAIN,
                b"--b1\r\nContent-Type: multipart/alternative; boundary=\"b2\"\r\n\r\n--b2\r\nContent-Type: text/plain\r\n\r\na\r\n--b2--\r\n\r\n--b1--\r\n",
            ]),
        ),
        (
            "attached message",
            mixed(&[
                b"--b1\r\nContent-Type: message/rfc822\r\n\r\nFrom: z@y.test\r\nSubject: in\r\nContent-Type: text/plain\r\n\r\nbody\r\n",
                END,
            ]),
        ),
        (
            "attached message with parts",
            mixed(&[
                b"--b1\r\nContent-Type: message/rfc822\r\n\r\nFrom: z@y.test\r\nContent-Type: multipart/alternative; boundary=\"b2\"\r\n\r\n",
                b"--b2\r\nContent-Type: text/plain\r\n\r\na\r\n--b2--\r\n",
                END,
            ]),
        ),
        (
            "attached eml",
            mixed(&[
                b"--b1\r\nContent-Type: application/octet-stream; name=\"a.eml\"\r\n\r\nFrom: z@y.test\r\nSubject: in\r\n\r\nbody\r\n",
                END,
            ]),
        ),
    ])
}


#[test]
fn a_blank_line_before_a_header_flags_the_part() -> Result<(), Box<dyn std::error::Error>> {
    all_flagged(&[
        (
            "space line",
            mixed(&[b"--b1\r\n \r\nContent-Type: text/plain; charset=shift_jis\r\n\r\nhello\r\n", END]),
        ),
        (
            "tab line",
            mixed(&[b"--b1\r\n\t\r\nContent-Type: text/plain; charset=shift_jis\r\n\r\nhello\r\n", END]),
        ),
        (
            "blank line inside a fold",
            b"From: a@x.test\r\nSubject: a\r\n  \r\nX: b\r\n\r\nhi\r\n".to_vec(),
        ),
    ])
}


#[test]
fn a_line_with_no_colon_flags_the_part() -> Result<(), Box<dyn std::error::Error>> {
    all_flagged(&[
        (
            "garbage in a part",
            mixed(&[b"--b1\r\ngarbage\r\nContent-Type: text/plain; charset=shift_jis\r\n\r\nhello\r\n", END]),
        ),
        ("garbage first in the message", b"garbage\r\nFrom: a@x.test\r\n\r\nhi\r\n".to_vec()),
        ("a colon first", b"From: a@x.test\r\n: x\r\n\r\nhi\r\n".to_vec()),
    ])
}


#[test]
fn a_bare_carriage_return_flags_the_part() -> Result<(), Box<dyn std::error::Error>> {
    all_flagged(&[(
        "hidden header",
        mixed(&[b"--b1\r\nX-A: b\rContent-Type: text/plain; charset=shift_jis\r\n\r\nhello\r\n", END]),
    )])
}


#[test]
fn a_header_name_outside_the_ftext_bytes_flags_the_part() -> Result<(), Box<dyn std::error::Error>> {
    all_flagged(&[
        (
            "space before the colon",
            mixed(&[b"--b1\r\nContent-Type : text/plain\r\n\r\nhello\r\n", END]),
        ),
        (
            "space inside the name",
            mixed(&[b"--b1\r\nCon tent-Type: text/plain\r\n\r\nhello\r\n", END]),
        ),
        ("8-bit name", mixed(&[b"--b1\r\nX-\xe9: b\r\n\r\nhello\r\n", END])),
        ("subject with a space", b"From: a@x.test\r\nSubject : a\r\n\r\nhi\r\n".to_vec()),
        ("byte order mark", b"\xef\xbb\xbfFrom: a@x.test\r\n\r\nhi\r\n".to_vec()),
        ("quoted mbox line", b">From a@x.test\r\nFrom: a@x.test\r\n\r\nhi\r\n".to_vec()),
    ])
}


#[test]
fn a_line_starting_with_two_dashes_flags_the_part() -> Result<(), Box<dyn std::error::Error>> {
    all_flagged(&[(
        "dashes header",
        mixed(&[b"--b1\r\n--x: y\r\nContent-Type: text/plain\r\n\r\nhi\r\n", END]),
    )])
}


#[test]
fn a_fold_first_in_the_region_flags_the_part() -> Result<(), Box<dyn std::error::Error>> {
    all_flagged(&[
        (
            "fold of nothing",
            mixed(&[b"--b1\r\n continued text\r\nContent-Type: text/plain\r\n\r\nhi\r\n", END]),
        ),
        (
            "fold of a header",
            mixed(&[b"--b1\r\n Content-Type: text/plain; charset=shift_jis\r\n\r\nhello\r\n", END]),
        ),
    ])
}


#[test]
fn an_mbox_line_is_allowed_only_first_and_only_as_an_unknown_name() -> Result<(), Box<dyn std::error::Error>> {
    all_flagged(&[
        ("later in the region", b"From: a@x.test\r\nFrom a b: c\r\n\r\nhi\r\n".to_vec()),
        ("a known header name", b"From : a@x.test\r\nSubject: s\r\n\r\nhi\r\n".to_vec()),
    ])
}


#[test]
fn a_delimiter_that_is_not_exactly_a_delimiter_line_flags_the_part() -> Result<(), Box<dyn std::error::Error>> {
    all_flagged(&[
        (
            "in the middle of a line",
            mixed(&[b"x--b1\r\nContent-Type: text/plain\r\n\r\nhi\r\n", END]),
        ),
        ("with a suffix", mixed(&[b"--b1junk\r\nContent-Type: text/plain\r\n\r\nhi\r\n", END])),
        (
            "second part with garbage",
            mixed(&[PLAIN, b"--b1\r\nbad\r\nContent-Type: text/plain\r\n\r\nb\r\n", END]),
        ),
    ])
}


#[test]
fn a_container_without_its_close_delimiter_flags_the_part() -> Result<(), Box<dyn std::error::Error>> {
    all_flagged(&[
        ("no close", mixed(&[PLAIN])),
        ("junk after the close", mixed(&[PLAIN, b"--b1--x\r\n"])),
        ("carriage return after the close", mixed(&[PLAIN, b"--b1--\rxx"])),
        (
            "adjacent delimiters",
            mixed(&[
                b"--b1\r\nContent-Type: multipart/alternative; boundary=\"b2\"\r\n\r\n--b2\r\nContent-Type: text/plain\r\n\r\na\r\n",
                b"--b2----b1\r\nContent-Type: text/plain\r\n\r\nz\r\n--b1--\r\n",
            ]),
        ),
        (
            "no blank line before the next delimiter",
            b"From: a@x.test\r\nContent-Type: multipart/mixed; boundary=\"a:b\"\r\n\r\n--a:b\r\nX-A: 1\r\n--a:b--\r\n".to_vec(),
        ),
    ])
}


#[test]
fn a_boundary_the_crate_may_read_differently_flags_the_part() -> Result<(), Box<dyn std::error::Error>> {
    let container = |content_type: &[u8]| {
        joined(&[
            b"From: a@x.test\r\nContent-Type: ",
            content_type,
            b"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b1--\r\n",
        ])
    };
    all_flagged(&[
        ("duplicated boundary", container(b"multipart/mixed; boundary=\"b1\"; boundary=\"b2\"")),
        ("continuation", container(b"multipart/mixed; boundary*0=\"b\"; boundary*1=\"1\"")),
        ("single continuation", container(b"multipart/mixed; boundary*0*=us-ascii''b1")),
        ("backslash", container(b"multipart/mixed; boundary=\"b\\1\"")),
        ("encoded word", container(b"multipart/mixed; boundary=\"=?utf-8?q?b1?=\"")),
        ("not UTF-8", container(b"multipart/mixed; boundary=\"b1\"; x=\xff")),
    ])?;
    none_flagged(&[("plain boundary", container(b"multipart/mixed; boundary=\"b1\""))])
}


#[test]
fn a_duplicated_content_type_flags_any_part() -> Result<(), Box<dyn std::error::Error>> {
    all_flagged(&[
        ("root", b"From: a@x.test\r\nContent-Type: text/plain\r\nContent-Type: text/html\r\n\r\nhi\r\n".to_vec()),
        (
            "container",
            b"From: a@x.test\r\nContent-Type: text/plain\r\nContent-Type: multipart/mixed; boundary=b1\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b1--\r\n"
                .to_vec(),
        ),
        (
            "binary child",
            mixed(&[b"--b1\r\nContent-Type: application/pdf\r\nContent-Type: text/plain\r\n\r\nxx\r\n", END]),
        ),
    ])
}


#[test]
fn an_attached_message_is_judged_at_its_own_level() -> Result<(), Box<dyn std::error::Error>> {
    all_flagged(&[
        (
            "inline rfc822",
            mixed(&[
                b"--b1\r\nContent-Type: message/rfc822\r\n\r\nFrom: z@y.test\r\n \r\nSubject: in\r\n\r\nbody\r\n",
                END,
            ]),
        ),
        (
            "eml attachment",
            mixed(&[
                b"--b1\r\nContent-Type: application/octet-stream; name=\"a.eml\"\r\n\r\nFrom: z@y.test\r\nbad line\r\nSubject: in\r\n\r\nbody\r\n",
                END,
            ]),
        ),
    ])
}


#[test]
fn a_region_over_the_bound_flags_the_part_and_one_under_it_does_not() -> Result<(), Box<dyn std::error::Error>> {
    let boundary_lines = MAX_HEADER_REGION_BYTES / LONG_LINE_BYTES;
    let under = run(&long_header_mail(boundary_lines - LINE_MARGIN))?;
    assert!(
        !under.uncertain_reasons.iter().any(|reason| reason == REASON),
        "{:?}",
        under.uncertain_reasons
    );
    let over = run(&long_header_mail(boundary_lines + LINE_MARGIN))?;
    assert!(over.uncertain_reasons.iter().any(|reason| reason == REASON));
    assert_eq!(over.counts.header_region_ambiguous, 1);
    Ok(())
}


#[test]
fn only_the_parts_inside_the_part_limit_are_judged() -> Result<(), Box<dyn std::error::Error>> {
    let raw = mixed(&[PLAIN, b"--b1\r\nbad\r\nContent-Type: text/plain\r\n\r\nb\r\n", END]);
    let wide = triage_with(&raw, &[], &ReporterPolicy::default(), &Limits::default())?;
    assert_eq!(wide.counts.header_region_ambiguous, 1);
    let narrow = triage_with(
        &raw,
        &[],
        &ReporterPolicy::default(),
        &Limits {
            parts: PART_LIMIT,
            ..Limits::default()
        },
    )?;
    assert_eq!(narrow.counts.header_region_ambiguous, 0);
    assert!(narrow.counts.parts_skipped > 0);
    Ok(())
}


#[test]
fn the_merge_compares_each_line_with_the_listed_offset() -> Result<(), Box<dyn std::error::Error>> {
    let region = b"X-A: 1\r\nX-B: 2\r\n\r\n";
    let second = FIRST + LINE_LENGTH;
    assert!(!lines_ambiguous(region, FIRST as usize, &[header(FIRST), header(second)]));
    assert!(
        lines_ambiguous(region, FIRST as usize, &[header(FIRST), header(second + 1)]),
        "right count, wrong offset"
    );
    assert!(
        lines_ambiguous(region, FIRST as usize, &[header(FIRST)]),
        "a line mail-parser did not list"
    );
    assert!(
        lines_ambiguous(region, FIRST as usize, &[header(FIRST), header(second), header(second + GAP)]),
        "a listed header with no line"
    );
    assert!(lines_ambiguous(region, FIRST as usize, &[]), "no listed header at all");
    Ok(())
}


#[test]
fn the_region_must_end_with_exactly_one_empty_line() -> Result<(), Box<dyn std::error::Error>> {
    let listed = [header(0)];
    assert!(!lines_ambiguous(b"X-A: 1\r\n\r\n", 0, &listed));
    assert!(!lines_ambiguous(b"X-A: 1\n\n", 0, &listed));
    assert!(
        lines_ambiguous(b"X-A: 1\r\n\r\nX-B: 2\r\n\r\n", 0, &listed),
        "an empty line before the last"
    );
    assert!(lines_ambiguous(b"X-A: 1\r\nX-B: 2\r\n", 0, &listed), "the last line is a header");
    assert!(lines_ambiguous(b"X-A: 1\r\n\r", 0, &listed), "no final line feed");
    assert!(!lines_ambiguous(b"\r\n", 0, &[]));
    Ok(())
}
