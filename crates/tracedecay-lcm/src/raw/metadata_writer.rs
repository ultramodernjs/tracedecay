//! Receipt-normalizing raw metadata writes. Call inside the registered writer
//! transaction; an inner savepoint also rolls dictionary insertions back on CAS failure.

use tracedecay_runtime_core::db::engine::{Executor, params};

use crate::LcmError;

pub async fn compare_and_swap_raw_metadata(
    conn: &(impl Executor + ?Sized),
    store_id: i64,
    provider: &str,
    message_id: &str,
    expected_stored: Option<&str>,
    replacement: Option<&str>,
) -> Result<(), LcmError> {
    conn.execute_batch("SAVEPOINT lcm_raw_metadata_cas").await?;
    let result = async {
        let metadata = super::receipt_store::normalize(conn, replacement).await?;
        let changed = conn
            .execute(
                "UPDATE lcm_raw_messages SET metadata_json = ?1
             WHERE store_id = ?2 AND provider = ?3 AND message_id = ?4 AND metadata_json IS ?5",
                params![
                    metadata.as_deref(),
                    store_id,
                    provider,
                    message_id,
                    expected_stored
                ],
            )
            .await?;
        if changed != 1 {
            return Err(LcmError::Db(
                "stored metadata changed during metadata update".to_owned(),
            ));
        }
        Ok(())
    }
    .await;
    match result {
        Ok(()) => {
            conn.execute_batch("RELEASE lcm_raw_metadata_cas").await?;
            Ok(())
        }
        Err(error) => {
            conn.execute_batch("ROLLBACK TO lcm_raw_metadata_cas; RELEASE lcm_raw_metadata_cas")
                .await?;
            Err(error)
        }
    }
}
