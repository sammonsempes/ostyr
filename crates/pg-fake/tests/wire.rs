use pg_fake::fake::{
    authenticate, be_i32, be_u16, bind_params, cstring, data_row, error_frame, format_of, frame, int8_cell, nullable_row, parameter_count,
    parameter_oid, read_message, ready, render_param, row_description, rows_frames, rows_of, serve_messages, typed_row_description, Reply, INT8_OID,
    MAX_MESSAGES, TEXT_OID,
};
use pg_fake::types::Handler;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::unbounded_channel;


const BUFFER: usize = 1_048_576;


const DRAIN_LIMIT: usize = 2000;


const TOO_MANY: usize = 40_000;


const FOUR: usize = 4;


const PAIR: usize = 2;


const SEVEN: i32 = 7;


const INT4: i32 = 23;


const STARTUP_LENGTH: i32 = 16;


const STARTUP_BODY: usize = 12;


const CLEARTEXT: i32 = 3;


const BE_I32_VALUE: i32 = 256;


const CUT: usize = 3;


fn by_sql(reply: Reply) -> Handler {
    Arc::new(move |sql| {
        if sql.contains("DROP") {
            Reply::Drop
        } else if sql.contains("ERR") {
            Reply::Error("42601")
        } else {
            reply.clone()
        }
    })
}


fn query(sql: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(frame(b'Q', format!("{sql}\0").as_bytes())?)
}


fn parse(sql: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(frame(b'P', format!("\0{sql}\0\0\0").as_bytes())?)
}


fn bind(params: &[&str], formats: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut body = b"\0\0".to_vec();
    body.extend_from_slice(&u16::try_from(formats.len() / PAIR)?.to_be_bytes());
    body.extend_from_slice(formats);
    body.extend_from_slice(&u16::try_from(params.len())?.to_be_bytes());
    params.iter().try_for_each(|param| {
        body.extend_from_slice(&i32::try_from(param.len())?.to_be_bytes());
        body.extend_from_slice(param.as_bytes());
        Ok::<(), Box<dyn Error>>(())
    })?;
    body.extend_from_slice(&[0, 0]);
    Ok(frame(b'B', &body)?)
}


fn drain(receiver: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> Vec<String> {
    std::iter::repeat_with(|| receiver.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


async fn run(handler: Handler, input: Vec<u8>) -> Result<(Vec<u8>, Vec<String>), Box<dyn Error>> {
    let (mut client, mut server) = duplex(BUFFER);
    client.write_all(&input).await?;
    client.shutdown().await?;
    let (sender, mut receiver) = unbounded_channel();
    serve_messages(&mut server, &handler, &sender).await?;
    drop(server);
    let mut output = Vec::new();
    client.read_to_end(&mut output).await?;
    Ok((output, drain(&mut receiver)))
}


fn joined(parts: Vec<Vec<u8>>) -> Vec<u8> {
    parts.concat()
}


#[tokio::test]
async fn simple_queries_answer_each_reply_and_drop_ends_the_session() -> Result<(), Box<dyn Error>> {
    let rows = Reply::Rows(vec![vec!["a".to_owned(), "b".to_owned()]]);
    let input = joined(vec![query("SELECT 1")?, query("ERR")?, query("DROP")?, query("NEVER")?]);
    let (output, statements) = run(by_sql(rows.clone()), input).await?;
    let expected = joined(vec![
        rows_frames(&rows, true)?,
        frame(b'C', b"OK\0")?,
        ready()?,
        error_frame("42601")?,
        ready()?,
    ]);
    assert_eq!(output, expected);
    assert_eq!(statements, ["SELECT 1", "ERR", "DROP"]);
    let (done_output, _) = run(by_sql(Reply::Done), query("SELECT 1")?).await?;
    assert_eq!(done_output, joined(vec![frame(b'C', b"OK\0")?, ready()?]));
    Ok(())
}


#[tokio::test]
async fn terminate_ends_the_session() -> Result<(), Box<dyn Error>> {
    let input = joined(vec![query("ONE")?, frame(b'X', &[])?, query("TWO")?]);
    let (_, statements) = run(by_sql(Reply::Done), input).await?;
    assert_eq!(statements, ["ONE"]);
    Ok(())
}


#[tokio::test]
async fn the_extended_flow_describes_binds_executes_and_closes() -> Result<(), Box<dyn Error>> {
    let rows = Reply::Rows(vec![vec!["a".to_owned()]]);
    let input = joined(vec![
        parse("SELECT $1 $2")?,
        bind(&["x", "y"], &[0, 0])?,
        frame(b'D', b"S\0")?,
        frame(b'D', b"P\0")?,
        frame(b'E', &[])?,
        frame(b'C', &[])?,
        frame(b'H', &[])?,
        frame(b'S', &[])?,
    ]);
    let (output, statements) = run(by_sql(rows.clone()), input).await?;
    let mut parameters = i16::try_from(PAIR)?.to_be_bytes().to_vec();
    parameters.extend_from_slice(&TEXT_OID.to_be_bytes());
    parameters.extend_from_slice(&TEXT_OID.to_be_bytes());
    let expected = joined(vec![
        frame(b'1', &[])?,
        frame(b'2', &[])?,
        frame(b't', &parameters)?,
        row_description(1, TEXT_OID)?,
        rows_frames(&rows, false)?,
        frame(b'C', b"OK\0")?,
        frame(b'3', &[])?,
        ready()?,
    ]);
    assert_eq!(output, expected);
    assert_eq!(statements, ["SELECT $1 $2", "PARAMS x|y"]);
    Ok(())
}


#[tokio::test]
async fn a_statement_without_rows_describes_no_data_and_integers_are_binary() -> Result<(), Box<dyn Error>> {
    let (output, _) = run(by_sql(Reply::Done), joined(vec![parse("SELECT 1")?, frame(b'D', b"S\0")?])).await?;
    assert_eq!(
        output,
        joined(vec![frame(b'1', &[])?, frame(b't', &0i16.to_be_bytes())?, frame(b'n', &[])?])
    );
    let ints = Reply::IntRows(vec![SEVEN]);
    let (int_output, _) = run(by_sql(ints.clone()), joined(vec![parse("SELECT 1")?, frame(b'E', &[])?])).await?;
    assert_eq!(
        int_output,
        joined(vec![frame(b'1', &[])?, data_row(&[SEVEN.to_be_bytes().to_vec()])?, frame(b'C', b"OK\0")?])
    );
    assert_eq!(rows_of(&ints), Some((vec![INT4], vec![vec![Some(SEVEN.to_be_bytes().to_vec())]])));
    Ok(())
}


#[tokio::test]
async fn an_extended_error_skips_messages_until_sync() -> Result<(), Box<dyn Error>> {
    let input = joined(vec![parse("ERR")?, bind(&[], &[])?, frame(b'E', &[])?, frame(b'S', &[])?]);
    let (output, _) = run(by_sql(Reply::Done), input).await?;
    assert_eq!(output, joined(vec![error_frame("42601")?, ready()?]));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_hang_reply_never_answers() -> Result<(), Box<dyn Error>> {
    let handler: Handler = Arc::new(|_| Reply::Hang);
    let (sender, _receiver) = unbounded_channel();
    let one_second = Duration::from_secs(1);
    let (mut simple_client, mut simple_server) = duplex(BUFFER);
    simple_client.write_all(&query("SELECT 1")?).await?;
    assert!(tokio::time::timeout(one_second, serve_messages(&mut simple_server, &handler, &sender))
        .await
        .is_err());
    let (mut extended_client, mut extended_server) = duplex(BUFFER);
    extended_client.write_all(&parse("SELECT 1")?).await?;
    assert!(tokio::time::timeout(one_second, serve_messages(&mut extended_server, &handler, &sender))
        .await
        .is_err());
    Ok(())
}


#[tokio::test]
async fn a_session_ends_after_the_message_cap() -> Result<(), Box<dyn Error>> {
    let sync = frame(b'S', &[])?;
    let input = sync.repeat(MAX_MESSAGES + 1);
    let (output, _) = run(by_sql(Reply::Done), input).await?;
    assert_eq!(output, ready()?.repeat(MAX_MESSAGES));
    Ok(())
}


#[tokio::test]
async fn read_message_reports_eof_bad_length_and_truncation() -> Result<(), Box<dyn Error>> {
    let (mut client, mut server) = duplex(BUFFER);
    client.shutdown().await?;
    assert!(read_message(&mut server).await?.is_none());
    let (mut negative_client, mut negative_server) = duplex(BUFFER);
    negative_client.write_all(b"Q").await?;
    negative_client.write_all(&(-1i32).to_be_bytes()).await?;
    assert!(read_message(&mut negative_server).await.is_err());
    let (mut short_client, mut short_server) = duplex(BUFFER);
    short_client
        .write_all(&frame(b'Q', b"abc")?.get(..FOUR + PAIR).map(<[u8]>::to_vec).ok_or("short")?)
        .await?;
    short_client.shutdown().await?;
    assert!(read_message(&mut short_server).await.is_err());
    let (mut whole_client, mut whole_server) = duplex(BUFFER);
    whole_client.write_all(&frame(b'Q', b"abc")?).await?;
    assert_eq!(read_message(&mut whole_server).await?, Some((b'Q', b"abc".to_vec())));
    Ok(())
}


#[tokio::test]
async fn authenticate_accepts_the_expected_password_only() -> Result<(), Box<dyn Error>> {
    let startup = [&STARTUP_LENGTH.to_be_bytes()[..], &[0u8; STARTUP_BODY]].concat();
    let (mut client, mut server) = duplex(BUFFER);
    let (sender, mut passwords) = unbounded_channel();
    client.write_all(&startup).await?;
    client.write_all(&frame(b'p', b"pw\0")?).await?;
    assert!(authenticate(&mut server, b"pw", &sender).await?);
    drop(server);
    let mut output = Vec::new();
    client.read_to_end(&mut output).await?;
    assert_eq!(
        output,
        joined(vec![frame(b'R', &CLEARTEXT.to_be_bytes())?, frame(b'R', &0i32.to_be_bytes())?, ready()?])
    );
    assert_eq!(passwords.recv().await, Some(b"pw".to_vec()));
    let (mut wrong_client, mut wrong_server) = duplex(BUFFER);
    wrong_client.write_all(&startup).await?;
    wrong_client.write_all(&frame(b'p', b"bad")?).await?;
    assert!(!authenticate(&mut wrong_server, b"pw", &sender).await?);
    assert_eq!(passwords.recv().await, Some(b"bad".to_vec()));
    let (mut silent_client, mut silent_server) = duplex(BUFFER);
    silent_client.write_all(&startup).await?;
    silent_client.shutdown().await?;
    assert!(authenticate(&mut silent_server, b"pw", &sender).await.is_err());
    let (mut negative_client, mut negative_server) = duplex(BUFFER);
    negative_client.write_all(&(-1i32).to_be_bytes()).await?;
    assert!(authenticate(&mut negative_server, b"pw", &sender).await.is_err());
    Ok(())
}


#[test]
fn helpers_decode_short_and_odd_input() -> Result<(), Box<dyn Error>> {
    assert_eq!(cstring(b"ab\0cd"), "ab");
    assert_eq!(cstring(b"ab"), "ab");
    assert_eq!((be_u16(&[1, 0]), be_u16(&[1])), (usize::try_from(BE_I32_VALUE)?, 0));
    assert_eq!((be_i32(&[0, 0, 1, 0]), be_i32(&[1])), (BE_I32_VALUE, 0));
    assert_eq!((parameter_count("SELECT $1, $3, $x, $"), parameter_count("SELECT 1")), (CUT, 0));
    assert!(row_description(TOO_MANY, TEXT_OID).is_err());
    assert!(data_row(&vec![Vec::new(); TOO_MANY]).is_err());
    assert_eq!(rows_of(&Reply::Rows(Vec::new())), Some((Vec::new(), Vec::new())));
    assert!(rows_of(&Reply::Done).is_none());
    assert!(rows_frames(&Reply::Done, true)?.is_empty());
    Ok(())
}


#[test]
fn bind_params_reads_text_parameters_and_tolerates_truncation() -> Result<(), Box<dyn Error>> {
    let body_of = |params: &[&str], formats: &[u8]| -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(bind(params, formats)?.get(FOUR + 1..).map(<[u8]>::to_vec).ok_or("short")?)
    };
    assert_eq!(bind_params(&body_of(&["a", "bc"], &[])?, &Reply::Done)?, ["a", "bc"]);
    assert_eq!(bind_params(&body_of(&["a"], &[0, 0, 0, 0])?, &Reply::Done)?, ["a"]);
    assert!(bind_params(&[], &Reply::Done)?.is_empty());
    let full = body_of(&["abc", "d"], &[])?;
    let cut = full.get(..full.len() - CUT).ok_or("short")?;
    assert_eq!(bind_params(cut, &Reply::Done)?, ["abc", ""]);
    Ok(())
}


const NINE: i64 = 9;


const INT8_LENGTH: i32 = 8;


const FAR: usize = 5;


const TWO_FORMATS: &[u8] = &[0, 2, 0, 0, 0, 1];


fn binary_bind(value: i64) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut body = b"\0\0\0\x01\0\x01\0\x01".to_vec();
    body.extend_from_slice(&INT8_LENGTH.to_be_bytes());
    body.extend_from_slice(&value.to_be_bytes());
    body.extend_from_slice(&[0, 0]);
    Ok(frame(b'B', &body)?)
}


fn typed() -> Reply {
    Reply::Typed {
        parameters: vec![INT8_OID],
        columns: vec![INT8_OID, TEXT_OID],
        rows: vec![vec![int8_cell(NINE), Some(b"t".to_vec())], vec![None, None]],
    }
}


#[tokio::test]
async fn a_typed_reply_describes_int8_parameters_and_columns_with_nulls() -> Result<(), Box<dyn Error>> {
    let input = joined(vec![
        parse("SELECT $1 $2")?,
        binary_bind(NINE)?,
        frame(b'D', b"S\0")?,
        frame(b'E', &[])?,
        frame(b'S', &[])?,
    ]);
    let (output, statements) = run(by_sql(typed()), input).await?;
    let mut parameters = i16::try_from(PAIR)?.to_be_bytes().to_vec();
    parameters.extend_from_slice(&INT8_OID.to_be_bytes());
    parameters.extend_from_slice(&TEXT_OID.to_be_bytes());
    let expected = joined(vec![
        frame(b'1', &[])?,
        frame(b'2', &[])?,
        frame(b't', &parameters)?,
        typed_row_description(&[INT8_OID, TEXT_OID])?,
        nullable_row(&[int8_cell(NINE), Some(b"t".to_vec())])?,
        nullable_row(&[None, None])?,
        frame(b'C', b"OK\0")?,
        ready()?,
    ]);
    assert_eq!(output, expected);
    assert_eq!(statements, ["SELECT $1 $2", "PARAMS 9"]);
    Ok(())
}


#[tokio::test]
async fn a_typed_reply_without_columns_describes_no_data() -> Result<(), Box<dyn Error>> {
    let reply = Reply::Typed {
        parameters: Vec::new(),
        columns: Vec::new(),
        rows: Vec::new(),
    };
    assert!(rows_of(&reply).is_none());
    let (output, _) = run(by_sql(reply), joined(vec![parse("SELECT 1")?, frame(b'D', b"S\0")?])).await?;
    assert_eq!(
        output,
        joined(vec![frame(b'1', &[])?, frame(b't', &0i16.to_be_bytes())?, frame(b'n', &[])?])
    );
    Ok(())
}


#[test]
fn parameter_oids_and_formats_fall_back_to_text() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        (parameter_oid(&typed(), 0), parameter_oid(&typed(), 1), parameter_oid(&Reply::Done, 0)),
        (INT8_OID, TEXT_OID, TEXT_OID)
    );
    assert_eq!(format_of(&[], 0), 0);
    assert_eq!(format_of(&[0, 0], 0), 0);
    assert_eq!(format_of(&[0, 1, 0, 1], FAR), 1);
    assert_eq!(
        (format_of(TWO_FORMATS, 0), format_of(TWO_FORMATS, 1), format_of(TWO_FORMATS, PAIR)),
        (0, 1, 0)
    );
    assert_eq!(render_param(&NINE.to_be_bytes(), 1, INT8_OID)?, "9");
    assert_eq!(
        render_param(&NINE.to_be_bytes(), 0, INT8_OID)?,
        String::from_utf8_lossy(&NINE.to_be_bytes())
    );
    assert_eq!(render_param(b"ab", 1, TEXT_OID)?, "ab");
    Ok(())
}


const OTHER_OID: i32 = 16;


const BAD_UTF8: &[u8] = &[0xff, 0xfe];


const FOUR_BYTES: i32 = 4;


const OTHER_BYTES: &[u8] = &[1, 0xab];


#[test]
fn render_param_follows_the_declared_type_not_the_length() -> Result<(), Box<dyn Error>> {
    assert_eq!(render_param(b"10.0.0.5", 1, TEXT_OID)?, "10.0.0.5");
    assert_eq!(render_param(&NINE.to_be_bytes(), 1, INT8_OID)?, "9");
    assert_eq!(render_param(&SEVEN.to_be_bytes(), 1, INT4)?, "7");
    assert_eq!(render_param(BAD_UTF8, 1, TEXT_OID)?, "invalid-utf8:2");
    assert_eq!(render_param(BAD_UTF8, 0, TEXT_OID)?, "invalid-utf8:2");
    assert_eq!(render_param(OTHER_BYTES, 1, OTHER_OID)?, "oid16:01ab");
    assert_eq!(render_param(b"abc", 1, INT8_OID), Err("22P03"));
    assert_eq!(render_param(b"abc", 1, INT4), Err("22P03"));
    Ok(())
}


#[tokio::test]
async fn a_wrong_length_int8_bind_is_an_error_until_sync() -> Result<(), Box<dyn Error>> {
    let mut body = b"\0\0\0\x01\0\x01\0\x01".to_vec();
    body.extend_from_slice(&FOUR_BYTES.to_be_bytes());
    body.extend_from_slice(b"abcd\0\0");
    let input = joined(vec![parse("SELECT $1")?, frame(b'B', &body)?, frame(b'E', &[])?, frame(b'S', &[])?]);
    let (output, statements) = run(by_sql(typed()), input).await?;
    assert_eq!(output, joined(vec![frame(b'1', &[])?, error_frame("22P03")?, ready()?]));
    assert_eq!(statements, ["SELECT $1"]);
    Ok(())
}
