//! Durable explanations for deleted observation identities, not source-byte coverage.
//!
//! Ranges are disjoint and coalesced in the retirement writer transaction. A
//! consumer verifies even a very large gap with one primary-key predecessor
//! lookup, without enumerating deleted identities or scanning the range table.

use tracedecay_runtime_core::db::engine::{Executor, QueryExecutor, params};
use tracedecay_store::{ProjectionStoreError, ProjectionStoreResult};

const OPERATION: &str = "observation retired sequence coverage";

/// Allocator state alone is not proof of retirement. Only retained observations
/// and committed retirement ranges contribute to the logical frontier.
pub(crate) const FRONTIER_SQL: &str = "SELECT MAX(
    COALESCE((SELECT sequence FROM observations ORDER BY sequence DESC LIMIT 1), 0),
    COALESCE((SELECT last_sequence FROM observation_retired_sequences ORDER BY first_sequence DESC LIMIT 1), 0))";

fn storage(error: impl std::error::Error + Send + Sync + 'static) -> ProjectionStoreError {
    ProjectionStoreError::storage(OPERATION, error)
}

/// Returns the covered end at `first`, or None for an unexplained identity.
pub(crate) async fn covered_through(
    conn: &impl QueryExecutor,
    first: i64,
) -> ProjectionStoreResult<Option<i64>> {
    let mut rows = conn
        .query(
            "SELECT last_sequence FROM observation_retired_sequences
             WHERE first_sequence <= ?1 ORDER BY first_sequence DESC LIMIT 1",
            params![first],
        )
        .await
        .map_err(storage)?;
    let end = rows
        .next()
        .await
        .map_err(storage)?
        .map(|row| row.get::<i64>(0).map_err(storage))
        .transpose()?;
    Ok(end.filter(|end| *end >= first))
}

/// Empty intervals are contiguous; nonempty intervals require explicit proof.
pub(crate) async fn covers(
    conn: &impl QueryExecutor,
    first: i64,
    last: i64,
) -> ProjectionStoreResult<bool> {
    if first > last {
        return Ok(true);
    }
    Ok(covered_through(conn, first)
        .await?
        .is_some_and(|end| end >= last))
}

/// Called only after this identity's cascade, with the range delete guard
/// lifted by the retirement owner. At most two indexed neighbors are removed;
/// merging does not introduce a scan proportional to past retirements.
pub(super) async fn record(conn: &impl Executor, sequence: i64) -> ProjectionStoreResult<()> {
    let mut first = sequence;
    let mut last = sequence;
    let mut rows = conn
        .query(
            "SELECT first_sequence, last_sequence FROM observation_retired_sequences
         WHERE first_sequence <= ?1 ORDER BY first_sequence DESC LIMIT 1",
            params![sequence],
        )
        .await
        .map_err(storage)?;
    let predecessor = rows
        .next()
        .await
        .map_err(storage)?
        .map(|row| -> ProjectionStoreResult<(i64, i64)> {
            Ok((
                row.get::<i64>(0).map_err(storage)?,
                row.get::<i64>(1).map_err(storage)?,
            ))
        })
        .transpose()?;
    drop(rows);
    if let Some((start, end)) = predecessor {
        if end >= sequence {
            return Err(ProjectionStoreError::ProvenanceCollision);
        }
        if end == sequence - 1 {
            first = start;
            conn.execute(
                "DELETE FROM observation_retired_sequences WHERE first_sequence=?1",
                params![start],
            )
            .await
            .map_err(storage)?;
        }
    }
    let mut rows = conn
        .query(
            "SELECT first_sequence, last_sequence FROM observation_retired_sequences
         WHERE first_sequence > ?1 ORDER BY first_sequence LIMIT 1",
            params![sequence],
        )
        .await
        .map_err(storage)?;
    let successor = rows
        .next()
        .await
        .map_err(storage)?
        .map(|row| -> ProjectionStoreResult<(i64, i64)> {
            Ok((
                row.get::<i64>(0).map_err(storage)?,
                row.get::<i64>(1).map_err(storage)?,
            ))
        })
        .transpose()?;
    drop(rows);
    if let Some((start, end)) = successor
        && sequence.checked_add(1) == Some(start)
    {
        last = end;
        conn.execute(
            "DELETE FROM observation_retired_sequences WHERE first_sequence=?1",
            params![start],
        )
        .await
        .map_err(storage)?;
    }
    conn.execute(
        "INSERT INTO observation_retired_sequences(first_sequence,last_sequence) VALUES (?1,?2)",
        params![first, last],
    )
    .await
    .map_err(storage)?;
    Ok(())
}
