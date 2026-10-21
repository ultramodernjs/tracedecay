-- Released observation/source bookkeeping DDL from 961456f270.
-- Retrieval-anchor DDL is installed by the unchanged canonical authority.
CREATE TABLE IF NOT EXISTS sanitization_receipts (
            receipt_id TEXT PRIMARY KEY,
            sanitizer_version TEXT NOT NULL,
            payload_digest TEXT NOT NULL,
            receipt_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS observations (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            observation_id TEXT NOT NULL UNIQUE,
            payload_digest TEXT NOT NULL,
            receipt_id TEXT NOT NULL,
            observation_json TEXT NOT NULL,
            committed_cursor_json TEXT NOT NULL,
            FOREIGN KEY(receipt_id) REFERENCES sanitization_receipts(receipt_id)
        );
        CREATE TABLE IF NOT EXISTS remote_writer_fences (
            authority_key TEXT PRIMARY KEY,
            writer_fence_json TEXT NOT NULL CHECK(json_valid(writer_fence_json)),
            frontier_sequence INTEGER NOT NULL CHECK(frontier_sequence >= 0),
            updated_at INTEGER NOT NULL
        ) STRICT;
        CREATE TABLE IF NOT EXISTS remote_observation_events (
            event_id TEXT PRIMARY KEY,
            frame_digest TEXT NOT NULL,
            enrollment_id TEXT NOT NULL,
            enrollment_revision INTEGER NOT NULL CHECK(enrollment_revision > 0),
            node_id TEXT NOT NULL,
            policy_revision INTEGER NOT NULL CHECK(policy_revision > 0),
            capture_sequence INTEGER NOT NULL CHECK(capture_sequence > 0),
            previous_event_id TEXT REFERENCES remote_observation_events(event_id),
            observation_id TEXT NOT NULL UNIQUE REFERENCES observations(observation_id),
            writer_fence_json TEXT NOT NULL CHECK(json_valid(writer_fence_json)),
            captured_at INTEGER NOT NULL,
            idempotency_key TEXT NOT NULL UNIQUE,
            command_digest TEXT NOT NULL,
            UNIQUE(enrollment_id, node_id, capture_sequence)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS observation_retrieval_anchors (
            observation_id TEXT PRIMARY KEY,
            anchor_id TEXT NOT NULL UNIQUE,
            FOREIGN KEY(observation_id) REFERENCES observations(observation_id),
            FOREIGN KEY(anchor_id) REFERENCES retrieval_anchors(anchor_id)
        );
        CREATE TABLE IF NOT EXISTS observation_repository_provenance (
            observation_id TEXT PRIMARY KEY,
            availability_json TEXT NOT NULL CHECK(json_valid(availability_json)),
            capture_json TEXT CHECK(capture_json IS NULL OR json_valid(capture_json)),
            retrieval_anchor_id TEXT UNIQUE,
            owner_json TEXT CHECK(owner_json IS NULL OR json_valid(owner_json)),
            CHECK((capture_json IS NULL) = (retrieval_anchor_id IS NULL)),
            CHECK((owner_json IS NULL) = (retrieval_anchor_id IS NULL)),
            FOREIGN KEY(observation_id) REFERENCES observations(observation_id),
            FOREIGN KEY(retrieval_anchor_id, owner_json)
                REFERENCES retrieval_anchors(anchor_id, owner_json)
        );
        CREATE TABLE IF NOT EXISTS observation_repository_captures (
            capture_id TEXT PRIMARY KEY,
            capture_json TEXT NOT NULL CHECK(json_valid(capture_json))
        );
        CREATE TABLE IF NOT EXISTS session_canonical_bodies (
            content_hash TEXT PRIMARY KEY,
            encoding TEXT NOT NULL CHECK(encoding IN ('identity', 'deflate')),
            body BLOB NOT NULL,
            uncompressed_bytes INTEGER NOT NULL CHECK(uncompressed_bytes >= 0)
        );
        CREATE TRIGGER IF NOT EXISTS observation_retrieval_anchors_immutable_update
        BEFORE UPDATE ON observation_retrieval_anchors BEGIN
            SELECT RAISE(ABORT, 'observation retrieval anchor bindings are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS observation_retrieval_anchors_immutable_delete
        BEFORE DELETE ON observation_retrieval_anchors BEGIN
            SELECT RAISE(ABORT, 'observation retrieval anchor bindings are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS observation_repository_provenance_immutable_update
        BEFORE UPDATE ON observation_repository_provenance BEGIN
            SELECT RAISE(ABORT, 'observation repository provenance is immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS observation_repository_provenance_immutable_delete
        BEFORE DELETE ON observation_repository_provenance BEGIN
            SELECT RAISE(ABORT, 'observation repository provenance is immutable');
        END;
        CREATE TABLE IF NOT EXISTS source_cursors (
            source_json TEXT NOT NULL,
            scope_json TEXT NOT NULL,
            cursor_json TEXT NOT NULL,
            PRIMARY KEY(source_json, scope_json)
        );
        CREATE TABLE IF NOT EXISTS source_cursor_advances (
            source_json TEXT NOT NULL,
            scope_json TEXT NOT NULL,
            coverage_json TEXT NOT NULL,
            reason TEXT NOT NULL,
            receipt_id TEXT,
            PRIMARY KEY(source_json, scope_json, coverage_json),
            FOREIGN KEY(receipt_id) REFERENCES sanitization_receipts(receipt_id)
        );
        CREATE TABLE IF NOT EXISTS observation_admission_refusals (
            observation_id TEXT NOT NULL,
            refused_payload_digest TEXT NOT NULL,
            retained_payload_digest TEXT NOT NULL,
            refused_at INTEGER NOT NULL,
            PRIMARY KEY(observation_id, refused_payload_digest),
            FOREIGN KEY(observation_id) REFERENCES observations(observation_id)
        );
        CREATE TRIGGER IF NOT EXISTS observation_admission_refusals_immutable_update
        BEFORE UPDATE ON observation_admission_refusals BEGIN
            SELECT RAISE(ABORT, 'observation admission refusals are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS observation_admission_refusals_immutable_delete
        BEFORE DELETE ON observation_admission_refusals BEGIN
            SELECT RAISE(ABORT, 'observation admission refusals are immutable');
        END;
        CREATE TABLE IF NOT EXISTS projection_queue (
            observation_id TEXT PRIMARY KEY,
            observation_sequence INTEGER NOT NULL UNIQUE,
            attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
            next_retry_at_micros INTEGER NOT NULL DEFAULT 0 CHECK(next_retry_at_micros >= 0),
            last_error TEXT,
            FOREIGN KEY(observation_id) REFERENCES observations(observation_id)
        );
        CREATE INDEX IF NOT EXISTS idx_retrieval_anchor_dispositions_release_due
            ON retrieval_anchor_dispositions(effective_at, sequence)
            WHERE state IN ('superseded', 'deleted');
CREATE TABLE IF NOT EXISTS observation_projection_provenance (
            projector_version TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            output_ordinal INTEGER NOT NULL DEFAULT 0 CHECK(output_ordinal >= 0),
            receipt_id TEXT NOT NULL,
            output_provider TEXT NOT NULL,
            output_message_id TEXT NOT NULL,
            output_digest TEXT NOT NULL,
            message_created INTEGER NOT NULL CHECK(message_created IN (0, 1)),
            retrieval_anchor_id TEXT REFERENCES retrieval_anchors(anchor_id),
            PRIMARY KEY(projector_version, observation_id, output_ordinal),
            FOREIGN KEY(observation_id) REFERENCES observations(observation_id),
            FOREIGN KEY(receipt_id) REFERENCES sanitization_receipts(receipt_id)
        );
        CREATE TABLE IF NOT EXISTS observation_projection_checkpoints (
            projector_version TEXT PRIMARY KEY,
            last_sequence INTEGER NOT NULL CHECK(last_sequence >= 0)
        );
        CREATE TABLE IF NOT EXISTS observation_projection_aliases (
            projector_version TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            output_provider TEXT NOT NULL,
            output_message_id TEXT NOT NULL,
            PRIMARY KEY(projector_version, observation_id),
            FOREIGN KEY(observation_id) REFERENCES observations(observation_id)
        );
        CREATE TABLE IF NOT EXISTS observation_projection_dispositions (
            projector_version TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            receipt_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            PRIMARY KEY(projector_version, observation_id),
            FOREIGN KEY(observation_id) REFERENCES observations(observation_id),
            FOREIGN KEY(receipt_id) REFERENCES sanitization_receipts(receipt_id)
        );
        CREATE TABLE IF NOT EXISTS observation_workflow_facts (
            projector_version TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            fact_ordinal INTEGER NOT NULL CHECK(fact_ordinal >= 0),
            receipt_id TEXT NOT NULL,
            observation_sequence INTEGER NOT NULL CHECK(observation_sequence > 0),
            provider TEXT NOT NULL,
            session_id TEXT NOT NULL,
            semantic_kind TEXT NOT NULL CHECK(
                semantic_kind IN ('goal', 'plan', 'todo_list', 'todo_item', 'task')
            ),
            provider_reference TEXT,
            item_id TEXT,
            parent_reference TEXT,
            list_reference TEXT,
            state TEXT,
            status TEXT,
            item_order INTEGER CHECK(item_order IS NULL OR item_order >= 0),
            native_revision TEXT,
            event_sequence INTEGER CHECK(event_sequence IS NULL OR event_sequence >= 0),
            source_sequence INTEGER CHECK(source_sequence IS NULL OR source_sequence >= 0),
            native_timestamp INTEGER,
            ordering_domain TEXT NOT NULL,
            content_json TEXT CHECK(content_json IS NULL OR json_valid(content_json)),
            content_text TEXT NOT NULL,
            output_digest TEXT NOT NULL,
            retrieval_anchor_id TEXT REFERENCES retrieval_anchors(anchor_id),
            PRIMARY KEY(projector_version, observation_id, fact_ordinal),
            FOREIGN KEY(observation_id) REFERENCES observations(observation_id),
            FOREIGN KEY(receipt_id) REFERENCES sanitization_receipts(receipt_id)
        );
        CREATE TABLE IF NOT EXISTS observation_provider_usage (
            projector_version TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            usage_ordinal INTEGER NOT NULL CHECK(usage_ordinal >= 0),
            receipt_id TEXT NOT NULL,
            observation_sequence INTEGER NOT NULL CHECK(observation_sequence > 0),
            scope_kind TEXT NOT NULL CHECK(scope_kind IN ('profile', 'project')),
            project_id TEXT CHECK(project_id IS NULL OR length(project_id) > 0),
            provider TEXT NOT NULL,
            model_json TEXT NOT NULL CHECK(json_valid(model_json)),
            native_scope TEXT NOT NULL CHECK(
                native_scope IN (
                    'request', 'message', 'turn', 'session', 'unknown', 'unavailable'
                )
            ),
            counter_semantics TEXT NOT NULL CHECK(
                counter_semantics IN ('delta', 'cumulative', 'unknown', 'unavailable')
            ),
            counters_json TEXT NOT NULL CHECK(json_valid(counters_json)),
            session_id TEXT NOT NULL,
            turn_id TEXT,
            message_id TEXT,
            request_id TEXT,
            native_kind TEXT NOT NULL,
            native_field TEXT NOT NULL,
            ordering_domain TEXT NOT NULL,
            source_start INTEGER NOT NULL CHECK(source_start >= 0),
            source_end INTEGER NOT NULL CHECK(source_end > source_start),
            native_timestamp INTEGER,
            CHECK(
                (scope_kind = 'profile' AND project_id IS NULL)
                OR (scope_kind = 'project' AND project_id IS NOT NULL)
            ),
            PRIMARY KEY(projector_version, observation_id, usage_ordinal),
            FOREIGN KEY(observation_id) REFERENCES observations(observation_id),
            FOREIGN KEY(receipt_id) REFERENCES sanitization_receipts(receipt_id)
        );
        CREATE TRIGGER IF NOT EXISTS observation_provider_usage_no_update
        BEFORE UPDATE ON observation_provider_usage
        BEGIN
            SELECT RAISE(ABORT, 'provider usage observations are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS observation_provider_usage_receipt_binding
        BEFORE INSERT ON observation_provider_usage
        WHEN NOT EXISTS (
            SELECT 1
            FROM observations
            WHERE observation_id = NEW.observation_id
              AND receipt_id = NEW.receipt_id
              AND sequence = NEW.observation_sequence
              AND json_extract(observation_json, '$.identity.scope.kind') = NEW.scope_kind
              AND json_extract(
                    observation_json, '$.identity.scope.project_id'
                  ) IS NEW.project_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'provider usage provenance does not match observation');
        END;
        CREATE TRIGGER IF NOT EXISTS observation_provider_usage_no_delete
        BEFORE DELETE ON observation_provider_usage
        BEGIN
            SELECT RAISE(ABORT, 'provider usage observations are immutable');
        END;
        CREATE TABLE IF NOT EXISTS observation_projection_rebuild_provider_usage (
            projector_version TEXT NOT NULL,
            generation TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            usage_ordinal INTEGER NOT NULL CHECK(usage_ordinal >= 0),
            receipt_id TEXT NOT NULL,
            observation_sequence INTEGER NOT NULL CHECK(observation_sequence > 0),
            scope_kind TEXT NOT NULL CHECK(scope_kind IN ('profile', 'project')),
            project_id TEXT CHECK(project_id IS NULL OR length(project_id) > 0),
            provider TEXT NOT NULL,
            model_json TEXT NOT NULL CHECK(json_valid(model_json)),
            native_scope TEXT NOT NULL CHECK(
                native_scope IN (
                    'request', 'message', 'turn', 'session', 'unknown', 'unavailable'
                )
            ),
            counter_semantics TEXT NOT NULL CHECK(
                counter_semantics IN ('delta', 'cumulative', 'unknown', 'unavailable')
            ),
            counters_json TEXT NOT NULL CHECK(json_valid(counters_json)),
            session_id TEXT NOT NULL,
            turn_id TEXT,
            message_id TEXT,
            request_id TEXT,
            native_kind TEXT NOT NULL,
            native_field TEXT NOT NULL,
            ordering_domain TEXT NOT NULL,
            source_start INTEGER NOT NULL CHECK(source_start >= 0),
            source_end INTEGER NOT NULL CHECK(source_end > source_start),
            native_timestamp INTEGER,
            CHECK(
                (scope_kind = 'profile' AND project_id IS NULL)
                OR (scope_kind = 'project' AND project_id IS NOT NULL)
            ),
            PRIMARY KEY (
                projector_version, generation, observation_id, usage_ordinal
            ),
            FOREIGN KEY(projector_version, generation)
                REFERENCES observation_projection_rebuilds(projector_version, generation)
                ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS observation_projection_rebuilds (
            projector_version TEXT PRIMARY KEY,
            generation TEXT NOT NULL,
            frontier_sequence INTEGER NOT NULL CHECK(frontier_sequence >= 0),
            aliases_staged_through INTEGER NOT NULL DEFAULT 0
                CHECK(aliases_staged_through >= 0),
            staged_through INTEGER NOT NULL DEFAULT 0 CHECK(staged_through >= 0),
            projected_rows INTEGER NOT NULL DEFAULT 0 CHECK(projected_rows >= 0),
            skipped_observations INTEGER NOT NULL DEFAULT 0 CHECK(skipped_observations >= 0),
            state TEXT NOT NULL CHECK(state IN ('aliasing', 'building', 'ready')),
            UNIQUE(projector_version, generation)
        );
        CREATE TABLE IF NOT EXISTS observation_projection_rebuild_aliases (
            projector_version TEXT NOT NULL,
            generation TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            output_provider TEXT NOT NULL,
            output_message_id TEXT NOT NULL,
            PRIMARY KEY(projector_version, generation, observation_id),
            FOREIGN KEY(projector_version, generation)
                REFERENCES observation_projection_rebuilds(projector_version, generation)
                ON DELETE CASCADE,
            FOREIGN KEY(observation_id) REFERENCES observations(observation_id)
        );
        CREATE TABLE IF NOT EXISTS observation_projection_rebuild_sessions (
            projector_version TEXT NOT NULL,
            generation TEXT NOT NULL,
            provider TEXT NOT NULL,
            session_id TEXT NOT NULL,
            session_json TEXT NOT NULL CHECK(json_valid(session_json)),
            PRIMARY KEY(projector_version, generation, provider, session_id),
            FOREIGN KEY(projector_version, generation)
                REFERENCES observation_projection_rebuilds(projector_version, generation)
                ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS observation_projection_rebuild_messages (
            projector_version TEXT NOT NULL,
            generation TEXT NOT NULL,
            output_provider TEXT NOT NULL,
            output_message_id TEXT NOT NULL,
            message_json TEXT NOT NULL CHECK(json_valid(message_json)),
            content_hash TEXT NOT NULL,
            PRIMARY KEY(projector_version, generation, output_provider, output_message_id),
            FOREIGN KEY(projector_version, generation)
                REFERENCES observation_projection_rebuilds(projector_version, generation)
                ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS observation_projection_rebuild_provenance (
            projector_version TEXT NOT NULL,
            generation TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            output_ordinal INTEGER NOT NULL CHECK(output_ordinal >= 0),
            receipt_id TEXT NOT NULL,
            output_provider TEXT NOT NULL,
            output_message_id TEXT NOT NULL,
            output_digest TEXT NOT NULL,
            message_created INTEGER NOT NULL CHECK(message_created IN (0, 1)),
            retrieval_anchor_id TEXT REFERENCES retrieval_anchors(anchor_id),
            PRIMARY KEY(projector_version, generation, observation_id, output_ordinal),
            FOREIGN KEY(projector_version, generation)
                REFERENCES observation_projection_rebuilds(projector_version, generation)
                ON DELETE CASCADE,
            FOREIGN KEY(observation_id) REFERENCES observations(observation_id),
            FOREIGN KEY(receipt_id) REFERENCES sanitization_receipts(receipt_id)
        );
        CREATE TABLE IF NOT EXISTS observation_projection_rebuild_dispositions (
            projector_version TEXT NOT NULL,
            generation TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            receipt_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            PRIMARY KEY(projector_version, generation, observation_id),
            FOREIGN KEY(projector_version, generation)
                REFERENCES observation_projection_rebuilds(projector_version, generation)
                ON DELETE CASCADE,
            FOREIGN KEY(observation_id) REFERENCES observations(observation_id),
            FOREIGN KEY(receipt_id) REFERENCES sanitization_receipts(receipt_id)
        );
        CREATE TABLE IF NOT EXISTS observation_projection_rebuild_workflow_facts (
            projector_version TEXT NOT NULL,
            generation TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            fact_ordinal INTEGER NOT NULL CHECK(fact_ordinal >= 0),
            receipt_id TEXT NOT NULL,
            observation_sequence INTEGER NOT NULL CHECK(observation_sequence > 0),
            provider TEXT NOT NULL,
            session_id TEXT NOT NULL,
            semantic_kind TEXT NOT NULL CHECK(
                semantic_kind IN ('goal', 'plan', 'todo_list', 'todo_item', 'task')
            ),
            provider_reference TEXT,
            item_id TEXT,
            parent_reference TEXT,
            list_reference TEXT,
            state TEXT,
            status TEXT,
            item_order INTEGER CHECK(item_order IS NULL OR item_order >= 0),
            native_revision TEXT,
            event_sequence INTEGER CHECK(event_sequence IS NULL OR event_sequence >= 0),
            source_sequence INTEGER CHECK(source_sequence IS NULL OR source_sequence >= 0),
            native_timestamp INTEGER,
            ordering_domain TEXT NOT NULL,
            content_json TEXT CHECK(content_json IS NULL OR json_valid(content_json)),
            content_text TEXT NOT NULL,
            output_digest TEXT NOT NULL,
            retrieval_anchor_id TEXT REFERENCES retrieval_anchors(anchor_id),
            PRIMARY KEY(projector_version, generation, observation_id, fact_ordinal),
            FOREIGN KEY(projector_version, generation)
                REFERENCES observation_projection_rebuilds(projector_version, generation)
                ON DELETE CASCADE,
            FOREIGN KEY(observation_id) REFERENCES observations(observation_id),
            FOREIGN KEY(receipt_id) REFERENCES sanitization_receipts(receipt_id)
        );
        -- Where each record of a file-byte source sits in the newest layout that
        -- offered it. `observation_id` is the identity admission derived, so a
        -- row may name a record the store refused and never holds.
        CREATE TABLE IF NOT EXISTS observation_source_presence (
            source_key TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            generation TEXT NOT NULL,
            start_offset INTEGER NOT NULL CHECK(start_offset >= 0),
            PRIMARY KEY(source_key, observation_id)
        ) WITHOUT ROWID;
        -- A rewrite of a source that has not yet been read to its end. Records
        -- the new generation does not offer by then are retired.
        CREATE TABLE IF NOT EXISTS observation_source_rewrites (
            source_key TEXT PRIMARY KEY,
            generation TEXT NOT NULL,
            retained_through INTEGER NOT NULL CHECK(retained_through >= 0)
        );
CREATE TABLE tracedecay_schema_version(component TEXT PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO tracedecay_schema_version VALUES ('observations-v2-canonical-autoincrement', 1), ('observations-unified-identity-v1', 1), ('observation-repository-captures-v1-shared', 1);
