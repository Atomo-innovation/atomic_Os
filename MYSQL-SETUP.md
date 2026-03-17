# Setting Up MySQL for MeshCentral User Accounts

MeshCentral **already supports MySQL** (and MariaDB) as a database backend. When you use MySQL, **all data is stored in MySQL**, including:

- **User accounts**: username, email, and **hashed passwords** (with salt) are stored in the database
- Meshes, devices, events, and other server data

New account creation (sign-up form) uses the same database: when a user creates an account, their username, email, and hashed password are stored via the MeshCentral DB layer, which writes to MySQL when MySQL is configured.

No code changes are required—only configuration.

---

## 1. Install and prepare MySQL

- Install **MySQL** (e.g. 5.7+) or **MariaDB** (e.g. 10.3+) on your server.
- Create a database (optional; MeshCentral can create it if the user has permission):
  ```sql
  CREATE DATABASE meshcentral CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  ```
- Create a dedicated user and grant privileges (this project uses user `atomo` and password `atomo@1234` by default):
  ```sql
  CREATE USER 'atomo'@'localhost' IDENTIFIED BY 'atomo@1234';
  GRANT ALL PRIVILEGES ON meshcentral.* TO 'atomo'@'localhost';
  FLUSH PRIVILEGES;
  ```

---

## 2. Configure MeshCentral to use MySQL

Edit your MeshCentral config file. It is usually at:

- `config.json` in the MeshCentral folder, or  
- `meshcentral-data/config.json`

Add a **`mysql`** (or **`mariadb`**) block under **`settings`**.

### Option A: Connection string

```json
{
  "settings": {
    "mysql": "mysql://USER:PASSWORD@HOST:PORT/DATABASE"
  }
}
```

Example (this project's default user is `atomo`):

```json
"mysql": "mysql://atomo:atomo%401234@127.0.0.1:3306/meshcentral"
```
Note: In connection strings, `@` in the password must be encoded as `%40`.

### Option B: Object (recommended for production)

```json
{
  "settings": {
    "mysql": {
      "host": "127.0.0.1",
      "port": 3306,
      "user": "atomo",
      "password": "atomo@1234",
      "database": "meshcentral"
    }
  }
}
```
(This is the default used in this project's `meshcentral-data/config.json`.)

For **MariaDB**, use **`mariadb`** instead of **`mysql`** with the same structure (or a MariaDB connection string).

Optional SSL (use real paths to your certs):

```json
"mysql": {
  "host": "127.0.0.1",
  "port": 3306,
  "user": "meshcentral",
  "password": "YourStrongPassword",
  "database": "meshcentral",
  "ssl": {
    "cacertpath": "/path/to/ca.pem",
    "dontcheckserveridentity": false
  }
}
```

---

## 3. Allow new user accounts (sign-up)

To let visitors **create new accounts** (username, email, password), ensure your domain has **NewAccounts** enabled in the config:

```json
"domains": {
  "": {
    "NewAccounts": true
  }
}
```

With this, the “Create account” flow will store new users (username, email, hashed password) in MySQL via MeshCentral’s existing logic.

---

## 4. Install dependencies and start

- From the MeshCentral directory run:
  ```bash
  npm install
  node node_modules/meshcentral
  ```
- **If using the config in this repo** (`meshcentral-data/config.json`, with user `atomo` / password `atomo@1234`), either:
  - Copy the `meshcentral-data` folder to the parent of the MeshCentral folder (so it becomes `../meshcentral-data`), or
  - Run with an explicit data path:  
    `node node_modules/meshcentral --datapath /path/to/MeshCentral-master/meshcentral-data`
- On first start with MySQL configured, MeshCentral will:
  - Install the `mysql2` (or `mariadb`) driver if needed
  - Create the database if it does not exist (when the DB user is allowed to)
  - Create the required tables (e.g. `main` where user records are stored)

User records are stored in the **`main`** table: each row has an `id` (e.g. `user/domain/username`), `type` = `user`, and a **`doc`** JSON column that contains the user object (name, email, salt, hash, etc.). Passwords are **never** stored in plain text—only salt and hash.

---

## 5. Command-line override (optional)

You can pass MySQL via the command line instead of (or overriding) config:

```bash
node node_modules/meshcentral --mysql "mysql://user:password@127.0.0.1:3306/meshcentral"
```

---

## Summary

| Goal                         | Action |
|-----------------------------|--------|
| Store user accounts in MySQL | Add **`settings.mysql`** (or **`mariadb`**) in `config.json` and start MeshCentral. |
| Allow new sign-ups          | Set **`domains."".NewAccounts": true`** (or the right domain key). |
| User data stored            | Username, email, and **hashed password + salt** in MySQL `main` table. |

No extra code is required; MeshCentral already uses the configured database (NeDB, MongoDB, PostgreSQL, MySQL, or MariaDB) for all persistence, including user account creation and login.
