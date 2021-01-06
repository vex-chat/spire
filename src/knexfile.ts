// Update with your config settings.
import path from "path";

import { Config } from "knex";

const knexTestConfig: Config = {
    client: "sqlite3",
    connection: ":memory:",
    useNullAsDefault: true,
    migrations: {
        directory: path.join(__dirname, "migrations"),
    },
};

const knexDevConfig: Config = {
    client: "sqlite3",
    connection: {
        filename: "./dev.sqlite3",
    },
};

export { knexTestConfig, knexDevConfig };
