-- Run this once to create a simple view of MeshCentral users.
-- Then you can just use:  SELECT * FROM meshcentral_users;

USE meshcentral;

CREATE OR REPLACE VIEW meshcentral_users AS
SELECT
  id,
  JSON_UNQUOTE(JSON_EXTRACT(doc, '$.name'))   AS username,
  JSON_UNQUOTE(JSON_EXTRACT(doc, '$.email'))   AS email,
  FROM_UNIXTIME(CAST(JSON_EXTRACT(doc, '$.creation') AS UNSIGNED)) AS created,
  FROM_UNIXTIME(CAST(JSON_EXTRACT(doc, '$.login') AS UNSIGNED))     AS last_login
FROM main
WHERE type = 'user';

-- Show users (you will see this when you run the file)
SELECT * FROM meshcentral_users;
