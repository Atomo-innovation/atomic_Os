-- Atomic Center — DB Browser helper views
-- Open: meshcentral-data/atomic-center.sqlite in DB Browser for SQLite
-- Apply once (MeshCentral stopped):  npm run db:views   (from MeshCentral-master)
--
-- In DB Browser: Browse Data → pick a view below (not eventids).

DROP VIEW IF EXISTS atomic_center_users;
CREATE VIEW atomic_center_users AS
SELECT
  id,
  domain,
  json_extract(doc, '$.name') AS username,
  json_extract(doc, '$.email') AS email,
  json_extract(doc, '$.creation') AS created_unix,
  datetime(json_extract(doc, '$.creation'), 'unixepoch') AS created_at,
  json_extract(doc, '$.login') AS last_login_unix,
  datetime(json_extract(doc, '$.login'), 'unixepoch') AS last_login_at,
  CASE WHEN json_extract(doc, '$.siteadmin') IS NOT NULL THEN 1 ELSE 0 END AS is_site_admin
FROM main
WHERE type = 'user';

DROP VIEW IF EXISTS atomic_center_device_groups;
CREATE VIEW atomic_center_device_groups AS
SELECT
  id,
  domain,
  json_extract(doc, '$.name') AS group_name,
  json_extract(doc, '$.desc') AS description,
  json_extract(doc, '$.mtype') AS mesh_type
FROM main
WHERE type = 'mesh';

DROP VIEW IF EXISTS atomic_center_devices;
CREATE VIEW atomic_center_devices AS
SELECT
  id,
  domain,
  json_extract(doc, '$.name') AS device_name,
  json_extract(doc, '$.host') AS hostname,
  json_extract(doc, '$.osdesc') AS os,
  json_extract(doc, '$.meshid') AS mesh_id
FROM main
WHERE type = 'node';

DROP VIEW IF EXISTS atomic_center_recent_events;
CREATE VIEW atomic_center_recent_events AS
SELECT
  id,
  time,
  domain,
  action,
  userid,
  nodeid,
  json_extract(doc, '$.msg') AS message
FROM events
ORDER BY time DESC
LIMIT 200;
