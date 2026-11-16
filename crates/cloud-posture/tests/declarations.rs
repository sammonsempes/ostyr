#[path = "common/types.rs"]
mod types;


use cloud_posture::declarations::{
    load_declarations, parse_declarations, valid_kubeconfig_path, MAX_CLUSTERS, MAX_DECLARATION_BYTES, MAX_KUBECONFIG_PATH_BYTES,
};
use cloud_posture::error::DeclarationError;
use core_pg::scope::tenant_of;
use types::TestResult;


const GOOD_PATH: &str = "/etc/rancher/k3s/k3s.yaml";


const TWO_CLUSTERS: usize = 2;


const REFUSED_ENTRIES: usize = 10;


const OVER_THE_LIMIT: usize = 65;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


fn document(entries: &[(&str, &str, &str)]) -> String {
    let lines = entries
        .iter()
        .map(|(name, file, context)| format!("  - name: \"{name}\"\n    kubeconfig_file: \"{file}\"\n    context: \"{context}\"\n"))
        .collect::<String>();
    format!("tenant: lab\nclusters:\n{lines}")
}


#[test]
fn a_good_file_keeps_every_cluster() -> TestResult {
    let parsed = parse_declarations(&document(&[("a", GOOD_PATH, "ctx-a"), ("b", "/srv/b.yaml", "ctx-b")]))?;
    assert_eq!(tenant_of(&parsed.tenant), "lab");
    assert_eq!(parsed.clusters.len(), TWO_CLUSTERS);
    assert!(parsed.refused.is_empty());
    assert_eq!(parsed.clusters.first().map(|cluster| cluster.context.as_str()), Some("ctx-a"));
    Ok(())
}


#[test]
fn a_leading_dash_or_an_added_argument_refuses_only_that_entry() -> TestResult {
    let long = format!("/{}", "a".repeat(MAX_KUBECONFIG_PATH_BYTES));
    let parsed = parse_declarations(&document(&[
        ("-x", GOOD_PATH, "c1"),
        ("n2", GOOD_PATH, "-x"),
        ("n3", "-/etc/k", "c3"),
        ("n4", GOOD_PATH, "--output-directory=/tmp"),
        ("n5", GOOD_PATH, "a b"),
        ("n6", "/etc/../etc/k", "c6"),
        ("n7", "/etc/k\u{202e}", "c7"),
        ("n8", &long, "c8"),
        ("n9", "/etc/a b", "c9"),
        ("n\u{202e}10", GOOD_PATH, "c10"),
        ("ok", GOOD_PATH, "good"),
    ]))?;
    assert_eq!(parsed.refused, (0..REFUSED_ENTRIES).collect::<Vec<_>>());
    assert_eq!(parsed.clusters.len(), 1);
    Ok(())
}


#[test]
fn the_path_grammar_edges() -> TestResult {
    let limit = format!("/{}", "a".repeat(MAX_KUBECONFIG_PATH_BYTES - 1));
    let over = format!("/{}", "a".repeat(MAX_KUBECONFIG_PATH_BYTES));
    assert!(valid_kubeconfig_path(&limit));
    assert!(!valid_kubeconfig_path(&over));
    assert!(!valid_kubeconfig_path("relative/k"));
    assert!(!valid_kubeconfig_path("/a/../b"));
    assert!(valid_kubeconfig_path("/a/..b/c"));
    Ok(())
}


#[test]
fn a_repeated_context_or_name_refuses_both_entries() -> TestResult {
    let by_context = parse_declarations(&document(&[
        ("a", GOOD_PATH, "same"),
        ("b", GOOD_PATH, "same"),
        ("c", GOOD_PATH, "other"),
    ]))?;
    assert_eq!(by_context.refused, vec![0, 1]);
    assert_eq!(by_context.clusters.len(), 1);
    let by_name = parse_declarations(&document(&[("same", GOOD_PATH, "x"), ("same", GOOD_PATH, "y"), ("c", GOOD_PATH, "z")]))?;
    assert_eq!(by_name.refused, vec![0, 1]);
    assert_eq!(by_name.clusters.len(), 1);
    Ok(())
}


#[test]
fn an_entry_with_an_unknown_key_or_the_wrong_shape_is_refused_alone() -> TestResult {
    let text = "tenant: lab\nclusters:\n  - name: a\n    kubeconfig_file: /k\n    context: c\n    extra: 1\n  - just a string\n  - name: ok\n    kubeconfig_file: /k\n    context: fine\n";
    let parsed = parse_declarations(text)?;
    assert_eq!(parsed.refused, vec![0, 1]);
    assert_eq!(parsed.clusters.len(), 1);
    Ok(())
}


#[test]
fn sixty_five_clusters_refuse_the_file_and_sixty_four_pass() -> TestResult {
    let entries = (0..=MAX_CLUSTERS)
        .map(|index| (format!("n{index}"), format!("c{index}")))
        .collect::<Vec<_>>();
    let build = |count: usize| {
        let lines = entries
            .iter()
            .take(count)
            .map(|(name, context)| format!("  - {{name: {name}, kubeconfig_file: /k, context: {context}}}\n"))
            .collect::<String>();
        format!("tenant: lab\nclusters:\n{lines}")
    };
    let refused = parse_declarations(&build(MAX_CLUSTERS + 1)).err().ok_or("accepted")?;
    assert!(matches!(
        refused,
        DeclarationError::TooManyClusters {
            count: OVER_THE_LIMIT,
            max: MAX_CLUSTERS
        }
    ));
    assert_eq!(parse_declarations(&build(MAX_CLUSTERS))?.clusters.len(), MAX_CLUSTERS);
    Ok(())
}


#[test]
fn a_bad_tenant_or_a_malformed_document_is_a_fixed_error() -> TestResult {
    let tenant = parse_declarations("tenant: \"-x\"\nclusters: []\n").err().ok_or("accepted")?;
    assert!(matches!(tenant, DeclarationError::Tenant(_)));
    let unknown = parse_declarations("tenant: lab\nclusters: []\nother: 1\n").err().ok_or("accepted")?;
    assert!(matches!(unknown, DeclarationError::Malformed));
    let missing = parse_declarations("tenant: lab\n").err().ok_or("accepted")?;
    assert!(matches!(missing, DeclarationError::Malformed));
    let syntax = parse_declarations("tenant: [lab\nSECRETWORD").err().ok_or("accepted")?;
    assert!(!format!("{syntax} {syntax:?}").contains("SECRETWORD"));
    Ok(())
}


#[test]
fn the_file_is_read_with_a_cap() -> TestResult {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let good = dir.path().join("good.yaml");
    std::fs::write(&good, document(&[("a", GOOD_PATH, "c")]))?;
    assert_eq!(load_declarations(&good)?.clusters.len(), 1);
    let large = dir.path().join("large.yaml");
    std::fs::write(&large, "a".repeat(usize::try_from(MAX_DECLARATION_BYTES)? + 1))?;
    assert!(matches!(load_declarations(&large), Err(DeclarationError::TooLarge { .. })));
    let binary = dir.path().join("binary.yaml");
    std::fs::write(&binary, NOT_UTF8)?;
    assert!(matches!(load_declarations(&binary), Err(DeclarationError::Malformed)));
    assert!(matches!(load_declarations(&dir.path().join("none.yaml")), Err(DeclarationError::Read(_))));
    Ok(())
}
