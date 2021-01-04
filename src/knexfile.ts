// Update with your config settings.
import path from "path";

import { Config } from "knex";

const test: Config = {
    client: "sqlite3",
    connection: ":memory:",
    useNullAsDefault: true,
    migrations: {
        directory: path.join(__dirname, "migrations"),
    },
};

const development: Config = {
    client: "sqlite3",
    connection: {
        filename: "./dev.sqlite3",
    },
};

export { test, development };
