# spire

![build](https://github.com/vex-chat/spire/workflows/build/badge.svg)

A vex server implementation in NodeJS.

## dev setup

steps:

```
git clone git@github.com:vex-chat/spire
cd spire
```

set up your .env file in the root of the project

### sample env file for mysql:

```
SQL_HOST=localhost
SQL_PORT=3306
SQL_PASSWORD=hunter2
SQL_USER=vex
SQL_DB_NAME=spire
DB_TYPE=mysql

API_PORT=16777
SOCKET_PORT=16778

CANARY=true
```

### sample env file for sqlite3:

```
DB_TYPE=sqlite3

API_PORT=16777
SOCKET_PORT=16778

CANARY=true
```

### start the project

```
yarn
yarn start
```
