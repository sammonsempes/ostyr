use crate::types::TestResult;
use agent_linux::error::IsolationError;
use agent_linux::nft::{read_stderr, read_stdout, run_nft, run_nft_deadline, run_nft_with, MAX_NFT_OUTPUT_BYTES, MAX_NFT_STDERR_BYTES};
use agent_linux::sensor::kill_group;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::Empty;


const SHORT_DEADLINE_MILLIS: u64 = 50;


const LONG_SLEEP_SECONDS: &str = "30";


const NOISE_BYTES: &str = "100000";


const EXIT_CODE: i32 = 3;


fn script(text: &str) -> Result<(tempfile::TempDir, Vec<String>), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("script.sh");
    fs::write(&path, text)?;
    Ok((dir, vec![path.display().to_string()]))
}


#[tokio::test]
async fn real_commands_are_bounded_in_output_status_and_encoding() -> TestResult {
    let sh = PathBuf::from("/bin/sh");
    let ok = run_nft_with(PathBuf::from("/bin/echo"), vec!["hello".to_owned()], kill_group).await?;
    assert_eq!(ok, "hello\n");
    assert!(matches!(
        run_nft_with(PathBuf::from("/usr/bin/yes"), Vec::new(), kill_group).await,
        Err(IsolationError::TooLarge(MAX_NFT_OUTPUT_BYTES))
    ));
    assert!(matches!(
        run_nft_with(PathBuf::from("/bin/false"), Vec::new(), kill_group).await,
        Err(IsolationError::Exit { code: Some(1), .. })
    ));
    assert!(matches!(
        run_nft_with(PathBuf::from("/usr/bin/printf"), vec!["\\377".to_owned()], kill_group).await,
        Err(IsolationError::Utf8(_))
    ));
    assert!(matches!(
        run_nft_with(PathBuf::from("/nonexistent/nft"), Vec::new(), kill_group).await,
        Err(IsolationError::Io(_))
    ));
    let (_keep, noisy) = script(&format!("head -c {NOISE_BYTES} /dev/zero >&2\necho out\nexit {EXIT_CODE}\n"))?;
    let outcome = run_nft_with(sh, noisy, kill_group).await;
    let (code, stderr) = match outcome {
        Err(IsolationError::Exit { code, stderr }) => Ok((code, stderr)),
        other => Err(format!("a failing script must be an Exit error: {other:?}")),
    }?;
    assert_eq!(code, Some(EXIT_CODE));
    assert_eq!(stderr.len() as u64, MAX_NFT_STDERR_BYTES);
    Ok(())
}


#[tokio::test]
async fn a_hung_command_times_out_and_the_production_runner_runs() -> TestResult {
    let outcome = run_nft_deadline(
        PathBuf::from("/bin/sleep"),
        vec![LONG_SLEEP_SECONDS.to_owned()],
        Duration::from_millis(SHORT_DEADLINE_MILLIS),
    )
    .await;
    assert!(matches!(outcome, Err(IsolationError::Timeout)));
    assert_eq!(run_nft(PathBuf::from("/bin/echo"), vec!["x".to_owned()]).await?, "x\n");
    Ok(())
}


#[tokio::test]
async fn a_missing_pipe_reads_as_empty() -> TestResult {
    assert!(read_stdout::<Empty>(None, 1).await?.is_empty());
    assert!(read_stderr::<Empty>(None, 1).await?.is_empty());
    Ok(())
}
