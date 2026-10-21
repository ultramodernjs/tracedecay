//! Read-only plans and digest-confirmed, bounded convergence of mutation history.
//! This rewrites only redundant encoding; no receipt, mutation or object identity expires.

use rusqlite::{Connection, Savepoint, params};
use serde::Serialize;
use tracedecay_domain::canonical_sha256;

use super::super::support::invalid;
use super::{ExternalSourceExecutor, load_binding, slim};

const MAX_ROWS: usize = 1_000;
const MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
struct MutationRow {
    rowid: i64,
    binding_id: String,
    mutation_digest: String,
    native_object: String,
    revision: String,
    original: String,
    compact: String,
}

/// An in-memory plan for one page. Persist only `next_cursor` after a successful
/// outer transaction commit; call planning again for the next page.
#[derive(Clone, Debug)]
pub struct MutationCompactionPlan {
    digest: String,
    after_rowid: i64,
    max_rows: usize,
    max_bytes: usize,
    rows: Vec<MutationRow>,
    has_more: bool,
}

impl MutationCompactionPlan {
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn scanned_rows(&self) -> usize {
        self.rows.len()
    }
    pub fn changed_rows(&self) -> usize {
        self.rows
            .iter()
            .filter(|row| row.original != row.compact)
            .count()
    }
    pub fn logical_bytes_saved(&self) -> usize {
        self.rows
            .iter()
            .map(|row| row.original.len().saturating_sub(row.compact.len()))
            .sum()
    }
    pub fn next_cursor(&self) -> Option<i64> {
        self.rows.last().map(|row| row.rowid)
    }
    pub fn has_more(&self) -> bool {
        self.has_more
    }
}

impl ExternalSourceExecutor {
    /// Plans at most 1,000 rows / 4 MiB of history, without DDL, markers or data writes.
    /// A row larger than the requested byte cap is refused rather than skipped.
    pub fn plan_mutation_compaction(
        &self,
        connection: &Connection,
        after_rowid: Option<i64>,
        max_rows: usize,
        max_bytes: usize,
    ) -> rusqlite::Result<MutationCompactionPlan> {
        if max_rows == 0 || max_bytes == 0 {
            return Err(invalid("mutation compaction requires positive page bounds"));
        }
        let max_rows = max_rows.min(MAX_ROWS);
        let max_bytes = max_bytes.min(MAX_BYTES);
        let after_rowid = after_rowid.unwrap_or(0);
        let mut statement = connection.prepare("SELECT rowid, binding_id, mutation_digest, native_object_digest, revision_digest, mutation_json FROM external_source_mutations_v1 WHERE rowid > ?1 ORDER BY rowid LIMIT ?2")?;
        let mut source = statement.query(params![after_rowid, max_rows as i64 + 1])?;
        let mut rows = Vec::new();
        let mut bytes = 0_usize;
        let mut has_more = false;
        while let Some(row) = source.next()? {
            let original: String = row.get(5)?;
            if rows.len() == max_rows
                || (!rows.is_empty() && bytes.saturating_add(original.len()) > max_bytes)
            {
                has_more = true;
                break;
            }
            if original.len() > max_bytes {
                return Err(invalid("mutation compaction row exceeds byte budget"));
            }
            let mut planned = MutationRow {
                rowid: row.get(0)?,
                binding_id: row.get(1)?,
                mutation_digest: row.get(2)?,
                native_object: row.get(3)?,
                revision: row.get(4)?,
                original,
                compact: String::new(),
            };
            let revision: i64 = connection.query_row("SELECT MAX(binding_revision) FROM external_source_binding_revisions_v1 WHERE binding_id = ?1", [&planned.binding_id], |row| row.get(0))?;
            let binding = load_binding(connection, &planned.binding_id, revision)?
                .immutable_identity()
                .map_err(invalid)?;
            let mutation = slim::hydrate_mutation(
                &planned.original,
                &binding,
                slim::MutationRowKeys {
                    native_object: &planned.native_object,
                    revision: &planned.revision,
                    mutation_digest: &planned.mutation_digest,
                },
            )?;
            if mutation.mutation_digest().as_str() != planned.mutation_digest
                || mutation.observation().native_object().digest().as_str() != planned.native_object
                || mutation.observation().revision().digest().as_str() != planned.revision
                || mutation.evidence().binding() != &binding
            {
                return Err(invalid(
                    "mutation compaction found conflicting history keys",
                ));
            }
            planned.compact = slim::slim_mutation(&mutation, &binding)?;
            // Validate the exact prospective stored form through the production reader.
            let restored = slim::hydrate_mutation(
                &planned.compact,
                &binding,
                slim::MutationRowKeys {
                    native_object: &planned.native_object,
                    revision: &planned.revision,
                    mutation_digest: &planned.mutation_digest,
                },
            )?;
            if restored != mutation {
                return Err(invalid("mutation compaction is not lossless"));
            }
            bytes += planned.original.len();
            rows.push(planned);
        }
        let path = connection.path().unwrap_or("");
        let schema: i64 = connection.query_row("PRAGMA schema_version", [], |row| row.get(0))?;
        let digest = canonical_sha256(&(
            "tracedecay.external-source.mutation-compaction.v1",
            path,
            schema,
            after_rowid,
            max_rows,
            max_bytes,
            &rows,
            has_more,
        ))
        .map_err(invalid)?
        .as_str()
        .to_owned();
        Ok(MutationCompactionPlan {
            digest,
            after_rowid,
            max_rows,
            max_bytes,
            rows,
            has_more,
        })
    }

    /// Requires the plan's exact digest and revalidates the page under the caller's
    /// write savepoint. An inner savepoint rolls every earlier rewrite back on error.
    pub fn apply_mutation_compaction(
        &self,
        savepoint: &Savepoint<'_>,
        plan: &MutationCompactionPlan,
        confirmed_digest: &str,
    ) -> rusqlite::Result<usize> {
        if confirmed_digest != plan.digest {
            return Err(invalid("mutation compaction plan confirmation mismatch"));
        }
        let current = self.plan_mutation_compaction(
            savepoint,
            Some(plan.after_rowid),
            plan.max_rows,
            plan.max_bytes,
        )?;
        if current.digest != plan.digest {
            return Err(invalid("mutation compaction plan is stale"));
        }
        savepoint.execute_batch("SAVEPOINT external_mutation_compaction")?;
        let outcome = (|| {
            let mut changed = 0;
            for row in &current.rows {
                if row.original == row.compact {
                    continue;
                }
                let updated = savepoint.execute("UPDATE external_source_mutations_v1 SET mutation_json = ?1 WHERE rowid = ?2 AND mutation_json = ?3", params![row.compact, row.rowid, row.original])?;
                if updated != 1 {
                    return Err(invalid("mutation compaction page changed during apply"));
                }
                changed += 1;
            }
            Ok(changed)
        })();
        match outcome {
            Ok(changed) => {
                savepoint.execute_batch("RELEASE external_mutation_compaction")?;
                Ok(changed)
            }
            Err(error) => {
                savepoint.execute_batch("ROLLBACK TO external_mutation_compaction; RELEASE external_mutation_compaction")?;
                Err(error)
            }
        }
    }
}
