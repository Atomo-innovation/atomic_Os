#!/bin/bash
# Show MeshCentral users from MySQL (simple wrapper)
# Usage: ./show-users.sh   (will ask for MySQL password)

mysql -u atomo -p meshcentral -e "
  SELECT 
    id AS user_id,
    JSON_UNQUOTE(JSON_EXTRACT(doc, '$.name')) AS username,
    JSON_UNQUOTE(JSON_EXTRACT(doc, '$.email')) AS email
  FROM main 
  WHERE type = 'user';
"
