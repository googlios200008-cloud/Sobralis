-- The runtime can check whether the database matches its release, but cannot
-- modify the migration ledger or inspect arbitrary database metadata.
CREATE FUNCTION public.runtime_schema_state()
RETURNS TABLE(name text,checksum text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $f$
 SELECT m.name,m.checksum FROM public.schema_migrations m ORDER BY m.name
$f$;
REVOKE ALL ON FUNCTION public.runtime_schema_state() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.runtime_schema_state() TO sobralis_runtime;
