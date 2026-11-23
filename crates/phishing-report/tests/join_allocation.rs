use phishing_report::model::Counts;
use phishing_report::urls::html_text;


#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;


const VALUES: usize = 20_000;


const OUTPUT_MULTIPLE: u64 = 16;


#[test]
fn joining_many_changed_attributes_copies_a_linear_number_of_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let html = "<a b='x&#9;'>".repeat(VALUES);
    let mut counts = Counts::default();
    let _profiler = dhat::Profiler::builder().testing().build();
    let before = dhat::HeapStats::get().total_bytes;
    let text = html_text(&html, &mut counts);
    let copied = dhat::HeapStats::get().total_bytes - before;
    let output = u64::try_from(text.len())?;
    assert!(text.len() > VALUES, "the attribute values must be appended");
    assert!(copied < output * OUTPUT_MULTIPLE, "copied {copied} bytes for an output of {output}");
    Ok(())
}
