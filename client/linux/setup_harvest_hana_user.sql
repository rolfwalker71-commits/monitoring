-- setup_harvest_hana_user.sql
-- Monitoring-Agent: read-only HANA user for AddOns + COMPANYDBS queries.
--
-- Where to run:
--   SAP HANA Studio / SAP HANA Database Explorer → SQL Console on the
--   TENANT database that holds SAP Business One data (not SYSTEMDB).
--
-- Multitenant: repeat in each tenant (e.g. BUP, PRD, …).
--
-- Password must match HANA_ADDONS_PASSWORD in /etc/monitoring-agent/agent.conf
-- (default from install_agent.sh: 0djKUt&xbLK0AYr).

-- Optional re-run cleanup:
-- DROP USER HARVEST;

CREATE USER HARVEST PASSWORD "0djKUt&xbLK0AYr" NO FORCE_FIRST_PASSWORD_CHANGE;

-- Agent queries (collect_and_send.sh):
--   SLDDATA.EXTENSIONS + SLDDATA.EXTENSIONDEPLOYMENTS  (Lightweight AddOns)
--   SBOCOMMON.SARI                                     (Legacy AddOns)
--   SLDDATA.COMPANYDBS                                 (Tenant DB list)

GRANT SELECT ON SCHEMA SLDDATA TO HARVEST;
GRANT SELECT ON SCHEMA SBOCOMMON TO HARVEST;

-- Quick verify (run as HARVEST in the same tenant):
-- SELECT COUNT(*) FROM "SLDDATA"."COMPANYDBS";
-- SELECT COUNT(*) FROM "SBOCOMMON"."SARI";
