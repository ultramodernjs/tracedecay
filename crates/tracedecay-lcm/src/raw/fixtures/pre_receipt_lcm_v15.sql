-- Released LCM v15 DDL from 961456f270, before receipt storage.
-- Deliberately independent of the current schema installer.
CREATE TABLE sessions(provider TEXT NOT NULL, session_id TEXT NOT NULL, project_key TEXT NOT NULL, project_path TEXT NOT NULL, PRIMARY KEY(provider, session_id));
CREATE TABLE IF NOT EXISTS session_canonical_bodies (
            content_hash TEXT PRIMARY KEY,
            encoding TEXT NOT NULL CHECK(encoding IN ('identity', 'deflate')),
            body BLOB NOT NULL,
            uncompressed_bytes INTEGER NOT NULL CHECK(uncompressed_bytes >= 0)
        );
        CREATE TABLE IF NOT EXISTS lcm_raw_messages (
            provider TEXT NOT NULL,
            message_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            store_id INTEGER PRIMARY KEY AUTOINCREMENT,
            role TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            timestamp INTEGER,
            content TEXT,
            content_hash TEXT NOT NULL,
            storage_kind TEXT NOT NULL CHECK(storage_kind IN ('inline', 'external')),
            payload_ref TEXT,
            placeholder_text TEXT,
            snippet_text TEXT NOT NULL GENERATED ALWAYS AS (
                CASE
                    WHEN content IS NULL THEN COALESCE(placeholder_text, '')
                    WHEN length(content) <= 4096 THEN content
                    ELSE substr(content, 1, 4054)
                        || char(10) || '[derived snippet truncated by tracedecay]'
                END
            ) VIRTUAL,
            index_text TEXT NOT NULL GENERATED ALWAYS AS (
                CASE
                    WHEN content IS NULL THEN COALESCE(placeholder_text, '')
                    WHEN length(content) <= 65536 THEN content
                    ELSE substr(content, 1, 65494)
                        || char(10) || '[derived snippet truncated by tracedecay]'
                END
            ) VIRTUAL,
            metadata_json TEXT,
            kind TEXT,
            model TEXT,
            tool_names TEXT,
            source_path TEXT,
            source_offset INTEGER,
            UNIQUE(provider, message_id),
            FOREIGN KEY(provider, session_id)
                REFERENCES sessions(provider, session_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_lcm_raw_session_order
            ON lcm_raw_messages(provider, session_id, store_id);
        CREATE INDEX IF NOT EXISTS idx_lcm_raw_session_id
            ON lcm_raw_messages(session_id);
        CREATE INDEX IF NOT EXISTS idx_lcm_raw_session_ordinal
            ON lcm_raw_messages(provider, session_id, ordinal);
        CREATE INDEX IF NOT EXISTS idx_lcm_raw_session_activity
            ON lcm_raw_messages(
                provider, session_id, timestamp, ordinal, message_id, kind, tool_names
            );
        CREATE INDEX IF NOT EXISTS idx_lcm_raw_timestamp
            ON lcm_raw_messages(timestamp);
        CREATE TABLE IF NOT EXISTS lcm_external_payloads (
            payload_ref TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            session_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            byte_count INTEGER NOT NULL,
            char_count INTEGER NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (unixepoch()),
            metadata_json TEXT,
            UNIQUE(provider, message_id, payload_ref),
            FOREIGN KEY(provider, session_id)
                REFERENCES sessions(provider, session_id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS lcm_gc_marks (
            payload_ref TEXT PRIMARY KEY,
            state TEXT NOT NULL CHECK(state IN ('unreferenced', 'missing')),
            first_seen_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT (unixepoch())
        );
        CREATE TABLE IF NOT EXISTS lcm_gc_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS lcm_lifecycle_state (
            provider TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            current_session_id TEXT NOT NULL,
            last_finalized_session_id TEXT,
            current_frontier_store_id INTEGER,
            last_finalized_frontier_store_id INTEGER,
            rollover_at INTEGER,
            reset_at INTEGER,
            maintenance_at INTEGER,
            boundary_skip_at INTEGER,
            updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
            PRIMARY KEY(provider, conversation_id)
        );
        CREATE TABLE IF NOT EXISTS lcm_maintenance_debt (
            provider TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            debt_id TEXT NOT NULL,
            debt_kind TEXT NOT NULL,
            from_store_id INTEGER,
            to_store_id INTEGER,
            metadata_json TEXT,
            created_at INTEGER NOT NULL DEFAULT (unixepoch()),
            PRIMARY KEY(provider, conversation_id, debt_id),
            FOREIGN KEY(provider, conversation_id)
                REFERENCES lcm_lifecycle_state(provider, conversation_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_lcm_maintenance_debt_kind
            ON lcm_maintenance_debt(provider, debt_kind, created_at);
CREATE VIRTUAL TABLE IF NOT EXISTS lcm_raw_messages_fts USING fts5(
        index_text, role, kind, model, tool_names,
        content='lcm_raw_messages',
        content_rowid='store_id'
    );
    CREATE TRIGGER IF NOT EXISTS lcm_raw_messages_fts_insert
        AFTER INSERT ON lcm_raw_messages BEGIN
            INSERT INTO lcm_raw_messages_fts(rowid, index_text, role, kind, model, tool_names)
            VALUES (NEW.store_id, NEW.index_text, NEW.role, NEW.kind, NEW.model, NEW.tool_names);
        END;
    CREATE TRIGGER IF NOT EXISTS lcm_raw_messages_fts_delete
        AFTER DELETE ON lcm_raw_messages BEGIN
            INSERT INTO lcm_raw_messages_fts(
                lcm_raw_messages_fts, rowid, index_text, role, kind, model, tool_names
            )
            VALUES (
                'delete', OLD.store_id, OLD.index_text, OLD.role, OLD.kind, OLD.model,
                OLD.tool_names
            );
        END;
    CREATE TRIGGER IF NOT EXISTS lcm_raw_messages_fts_update
        AFTER UPDATE ON lcm_raw_messages BEGIN
            INSERT INTO lcm_raw_messages_fts(
                lcm_raw_messages_fts, rowid, index_text, role, kind, model, tool_names
            )
            VALUES (
                'delete', OLD.store_id, OLD.index_text, OLD.role, OLD.kind, OLD.model,
                OLD.tool_names
            );
            INSERT INTO lcm_raw_messages_fts(rowid, index_text, role, kind, model, tool_names)
            VALUES (NEW.store_id, NEW.index_text, NEW.role, NEW.kind, NEW.model, NEW.tool_names);
        END;

    CREATE INDEX IF NOT EXISTS idx_lcm_gc_marks_state_first_seen
        ON lcm_gc_marks(state, first_seen_at);
    CREATE TRIGGER IF NOT EXISTS lcm_raw_messages_gc_candidate_delete
        AFTER DELETE ON lcm_raw_messages BEGIN
            INSERT INTO lcm_gc_marks(payload_ref, state, first_seen_at, updated_at)
            SELECT payload_ref, 'unreferenced', unixepoch(), unixepoch()
            FROM lcm_external_payloads
            WHERE provider = OLD.provider AND message_id = OLD.message_id
            ON CONFLICT(payload_ref) DO UPDATE SET
                state = 'unreferenced',
                first_seen_at = excluded.first_seen_at,
                updated_at = excluded.updated_at
            WHERE lcm_gc_marks.state <> 'unreferenced';
        END;
    CREATE TRIGGER IF NOT EXISTS lcm_raw_messages_gc_candidate_update
        AFTER UPDATE ON lcm_raw_messages
        WHEN OLD.content IS NOT NEW.content
          OR OLD.placeholder_text IS NOT NEW.placeholder_text
          OR OLD.metadata_json IS NOT NEW.metadata_json
          OR OLD.storage_kind IS NOT NEW.storage_kind
          OR OLD.payload_ref IS NOT NEW.payload_ref
          OR OLD.provider IS NOT NEW.provider
          OR OLD.message_id IS NOT NEW.message_id
          OR OLD.session_id IS NOT NEW.session_id
        BEGIN
            INSERT INTO lcm_gc_marks(payload_ref, state, first_seen_at, updated_at)
            SELECT payload_ref, 'unreferenced', unixepoch(), unixepoch()
            FROM lcm_external_payloads
            WHERE provider = OLD.provider AND message_id = OLD.message_id
            ON CONFLICT(payload_ref) DO UPDATE SET
                state = 'unreferenced',
                first_seen_at = excluded.first_seen_at,
                updated_at = excluded.updated_at
            WHERE lcm_gc_marks.state <> 'unreferenced';
        END;
CREATE TABLE IF NOT EXISTS session_canonical_body_references (
        owner_kind TEXT NOT NULL CHECK(owner_kind IN ('observation', 'raw')),
        owner_key TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        PRIMARY KEY(owner_kind, owner_key, content_hash)
    );
CREATE INDEX IF NOT EXISTS idx_session_canonical_body_references_hash
        ON session_canonical_body_references(content_hash);
CREATE TRIGGER IF NOT EXISTS lcm_raw_canonical_refs_insert
    AFTER INSERT ON lcm_raw_messages BEGIN
        INSERT OR IGNORE INTO session_canonical_body_references
            (owner_kind, owner_key, content_hash)
        VALUES ('raw', CAST(NEW.store_id AS TEXT), NEW.content_hash);
    END;
CREATE TRIGGER IF NOT EXISTS lcm_raw_canonical_refs_update
    AFTER UPDATE OF content_hash, store_id ON lcm_raw_messages BEGIN
        DELETE FROM session_canonical_body_references
        WHERE owner_kind = 'raw' AND owner_key = CAST(OLD.store_id AS TEXT);
        INSERT OR IGNORE INTO session_canonical_body_references
            (owner_kind, owner_key, content_hash)
        VALUES ('raw', CAST(NEW.store_id AS TEXT), NEW.content_hash);
    END;
CREATE TRIGGER IF NOT EXISTS lcm_raw_canonical_refs_delete
    AFTER DELETE ON lcm_raw_messages BEGIN
        DELETE FROM session_canonical_body_references
        WHERE owner_kind = 'raw' AND owner_key = CAST(OLD.store_id AS TEXT);
    END;

CREATE TABLE IF NOT EXISTS lcm_summary_convergence_queue (
    queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    session_id TEXT NOT NULL,
    newest_raw_store_id INTEGER NOT NULL,
    protection_frontier_store_id INTEGER NOT NULL DEFAULT 0,
    attempted_raw_store_id INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK(state IN ('pending', 'retryable', 'current', 'unavailable', 'permanent')),
    failure_code TEXT,
    failure_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at_ms INTEGER NOT NULL DEFAULT 0,
    attempt_generation INTEGER NOT NULL DEFAULT 0,
    raw_revision_generation INTEGER NOT NULL DEFAULT 0,
    stale_from_store_id INTEGER,
    UNIQUE(provider, session_id),
    FOREIGN KEY(provider, session_id)
        REFERENCES sessions(provider, session_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS lcm_summary_convergence_dirty_raw (
    provider TEXT NOT NULL,
    session_id TEXT NOT NULL,
    store_id INTEGER NOT NULL,
    rewind_frontier_store_id INTEGER NOT NULL,
    PRIMARY KEY(provider, session_id, store_id),
    FOREIGN KEY(provider, session_id)
        REFERENCES sessions(provider, session_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS lcm_summary_convergence_invalidation_work (
    provider TEXT NOT NULL,
    session_id TEXT NOT NULL,
    raw_store_id INTEGER NOT NULL,
    source_kind TEXT NOT NULL CHECK(source_kind IN ('raw_message', 'summary_node')),
    source_id TEXT NOT NULL,
    depth INTEGER NOT NULL CHECK(depth >= 0),
    after_node_id TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK(state IN ('pending', 'drained')),
    PRIMARY KEY(provider, session_id, raw_store_id, source_kind, source_id),
    FOREIGN KEY(provider, session_id, raw_store_id)
        REFERENCES lcm_summary_convergence_dirty_raw(provider, session_id, store_id)
        ON DELETE CASCADE
);


CREATE INDEX IF NOT EXISTS idx_lcm_summary_convergence_due
    ON lcm_summary_convergence_queue(
        next_attempt_at_ms, attempt_generation, queue_id
    )
    WHERE state IN ('pending', 'retryable');
CREATE TRIGGER IF NOT EXISTS lcm_summary_convergence_dirty_raw_seed
    AFTER INSERT ON lcm_summary_convergence_dirty_raw BEGIN
        INSERT INTO lcm_summary_convergence_invalidation_work (
            provider, session_id, raw_store_id,
            source_kind, source_id, depth, after_node_id
        ) VALUES (
            NEW.provider, NEW.session_id, NEW.store_id,
            'raw_message', CAST(NEW.store_id AS TEXT), 0, ''
        )
        ON CONFLICT(provider, session_id, raw_store_id, source_kind, source_id)
        DO NOTHING;
    END;
CREATE TRIGGER IF NOT EXISTS lcm_summary_convergence_raw_insert
    AFTER INSERT ON lcm_raw_messages BEGIN
        INSERT INTO lcm_summary_convergence_queue (
            provider, session_id, newest_raw_store_id, raw_revision_generation
        ) VALUES (NEW.provider, NEW.session_id, NEW.store_id, 1)
        ON CONFLICT(provider, session_id) DO UPDATE SET
            newest_raw_store_id = MAX(
                lcm_summary_convergence_queue.newest_raw_store_id,
                excluded.newest_raw_store_id
            ),
            state = CASE
                WHEN excluded.newest_raw_store_id
                     > lcm_summary_convergence_queue.attempted_raw_store_id
                THEN 'pending'
                ELSE lcm_summary_convergence_queue.state
            END,
            failure_code = CASE
                WHEN excluded.newest_raw_store_id
                     > lcm_summary_convergence_queue.attempted_raw_store_id
                THEN NULL
                ELSE lcm_summary_convergence_queue.failure_code
            END,
            failure_count = CASE
                WHEN excluded.newest_raw_store_id
                     > lcm_summary_convergence_queue.attempted_raw_store_id
                THEN 0
                ELSE lcm_summary_convergence_queue.failure_count
            END,
            next_attempt_at_ms = CASE
                WHEN excluded.newest_raw_store_id
                     > lcm_summary_convergence_queue.attempted_raw_store_id
                THEN 0
                ELSE lcm_summary_convergence_queue.next_attempt_at_ms
            END,
            raw_revision_generation =
                lcm_summary_convergence_queue.raw_revision_generation + 1;
    END;
CREATE TRIGGER IF NOT EXISTS lcm_summary_convergence_raw_unprotected_update
    AFTER UPDATE OF provider, session_id, role, ordinal, timestamp,
                    content_hash, storage_kind, payload_ref, metadata_json
                    ON lcm_raw_messages
    WHEN OLD.provider IS NOT NEW.provider
      OR OLD.session_id IS NOT NEW.session_id
      OR OLD.role IS NOT NEW.role
      OR OLD.ordinal IS NOT NEW.ordinal
      OR OLD.timestamp IS NOT NEW.timestamp
      OR OLD.content_hash IS NOT NEW.content_hash
      OR OLD.storage_kind IS NOT NEW.storage_kind
      OR OLD.payload_ref IS NOT NEW.payload_ref
      OR OLD.metadata_json IS NOT NEW.metadata_json
    BEGIN
        INSERT INTO lcm_summary_convergence_dirty_raw (
            provider, session_id, store_id, rewind_frontier_store_id
        ) VALUES (
            NEW.provider, NEW.session_id, NEW.store_id, MAX(0, NEW.store_id - 1)
        )
        ON CONFLICT(provider, session_id, store_id) DO NOTHING;
        INSERT INTO lcm_summary_convergence_queue (
            provider, session_id, newest_raw_store_id,
            protection_frontier_store_id, raw_revision_generation,
            stale_from_store_id
        ) VALUES (
            NEW.provider, NEW.session_id, NEW.store_id,
            CASE
              WHEN json_valid(NEW.metadata_json)
               AND json_extract(
                   NEW.metadata_json,
                   '$.ingest_protection.sanitization_receipt'
               ) IS NOT NULL
              THEN NEW.store_id
              ELSE MAX(0, NEW.store_id - 1)
            END,
            1,
            CASE
              WHEN OLD.role IS NOT NEW.role
                OR OLD.ordinal IS NOT NEW.ordinal
                OR OLD.timestamp IS NOT NEW.timestamp
                OR OLD.content_hash IS NOT NEW.content_hash
                OR OLD.storage_kind IS NOT NEW.storage_kind
                OR OLD.payload_ref IS NOT NEW.payload_ref
                OR OLD.metadata_json IS NOT NEW.metadata_json
              THEN NEW.store_id
              ELSE NULL
            END
        )
        ON CONFLICT(provider, session_id) DO UPDATE SET
            newest_raw_store_id = MAX(
                lcm_summary_convergence_queue.newest_raw_store_id,
                excluded.newest_raw_store_id
            ),
            protection_frontier_store_id = MIN(
                lcm_summary_convergence_queue.protection_frontier_store_id,
                excluded.protection_frontier_store_id
            ),
            attempted_raw_store_id = CASE
              WHEN excluded.stale_from_store_id IS NOT NULL
              THEN MIN(
                  lcm_summary_convergence_queue.attempted_raw_store_id,
                  MAX(0, excluded.stale_from_store_id - 1)
              )
              ELSE lcm_summary_convergence_queue.attempted_raw_store_id
            END,
            stale_from_store_id = CASE
              WHEN excluded.stale_from_store_id IS NULL
              THEN lcm_summary_convergence_queue.stale_from_store_id
              WHEN lcm_summary_convergence_queue.stale_from_store_id IS NULL
              THEN excluded.stale_from_store_id
              ELSE MIN(
                  lcm_summary_convergence_queue.stale_from_store_id,
                  excluded.stale_from_store_id
              )
            END,
            state = 'pending',
            failure_code = NULL,
            failure_count = 0,
            next_attempt_at_ms = 0,
            raw_revision_generation =
                lcm_summary_convergence_queue.raw_revision_generation + 1;
    END;

CREATE TABLE tracedecay_schema_version(component TEXT PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO tracedecay_schema_version VALUES ('lcm', 15);
