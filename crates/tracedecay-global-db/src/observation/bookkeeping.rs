//! Lossless normalization and explicitly authorized observation maintenance.

pub mod retire;
pub mod source_key_compaction;
pub(crate) mod source_keys;

#[cfg(test)]
mod source_key_compaction_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod source_schema_upgrade_tests;
