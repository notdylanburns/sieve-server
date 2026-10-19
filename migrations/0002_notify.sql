-- sieve_entries wakes the metadata cache; it excludes metadata tables so the cache's own writes
-- don't wake it again. sieve_applications tells clients their application list may have changed.
-- Postgres collapses identical notifications within a transaction, so bulk changes send one each.
CREATE FUNCTION sieve_notify_change() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    changed record;
    workspace uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        changed := OLD;
    ELSE
        changed := NEW;
    END IF;

    CASE TG_TABLE_NAME
        WHEN 'domains', 'videos' THEN
            workspace := changed.workspace_id;
        WHEN 'paths', 'domain_metadata' THEN
            SELECT domains.workspace_id INTO workspace
            FROM domains WHERE domains.id = changed.domain_id;
        WHEN 'path_metadata' THEN
            SELECT domains.workspace_id INTO workspace
            FROM paths JOIN domains ON domains.id = paths.domain_id
            WHERE paths.id = changed.path_id;
        WHEN 'video_metadata' THEN
            SELECT videos.workspace_id INTO workspace
            FROM videos WHERE videos.id = changed.video_id;
    END CASE;

    -- NULL when a cascade has already removed the parent; the parent's own trigger notifies.
    IF workspace IS NULL THEN
        RETURN NULL;
    END IF;

    PERFORM pg_notify('sieve_applications', workspace::text);

    IF TG_OP <> 'DELETE' AND TG_TABLE_NAME IN ('domains', 'paths', 'videos') THEN
        PERFORM pg_notify('sieve_entries', workspace::text);
    END IF;

    RETURN NULL;
END
$$;

CREATE TRIGGER domains_notify AFTER INSERT OR UPDATE OR DELETE ON domains
    FOR EACH ROW EXECUTE FUNCTION sieve_notify_change();
CREATE TRIGGER paths_notify AFTER INSERT OR UPDATE OR DELETE ON paths
    FOR EACH ROW EXECUTE FUNCTION sieve_notify_change();
CREATE TRIGGER videos_notify AFTER INSERT OR UPDATE OR DELETE ON videos
    FOR EACH ROW EXECUTE FUNCTION sieve_notify_change();
CREATE TRIGGER domain_metadata_notify AFTER INSERT OR UPDATE OR DELETE ON domain_metadata
    FOR EACH ROW EXECUTE FUNCTION sieve_notify_change();
CREATE TRIGGER path_metadata_notify AFTER INSERT OR UPDATE OR DELETE ON path_metadata
    FOR EACH ROW EXECUTE FUNCTION sieve_notify_change();
CREATE TRIGGER video_metadata_notify AFTER INSERT OR UPDATE OR DELETE ON video_metadata
    FOR EACH ROW EXECUTE FUNCTION sieve_notify_change();
