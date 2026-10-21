//! Offline-only operator entry point until the main CLI dispatcher is wired.
//! Usage: compact_offline PROFILE DATABASE MAX_PAGES [--apply PREVIEW_DIGEST]

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;
    use tracedecay_maintenance::offline_compaction::{
        compact_offline_v1, inspect_compaction_candidate_v1,
    };

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 && !(args.len() == 5 && args[3] == "--apply") {
        return Err(
            "usage: compact_offline PROFILE DATABASE MAX_PAGES [--apply PREVIEW_DIGEST]".into(),
        );
    }
    let profile = Path::new(&args[0]);
    let database = Path::new(&args[1]);
    let max_pages = args[2].parse()?;
    if args.len() == 3 {
        println!(
            "{}",
            serde_json::to_string_pretty(&inspect_compaction_candidate_v1(
                profile, database, max_pages
            )?)?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&compact_offline_v1(
                profile, database, &args[4], max_pages
            )?)?
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("offline compaction publication is currently supported only on Unix");
    std::process::exit(1);
}
