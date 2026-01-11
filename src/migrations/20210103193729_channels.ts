// import * as Knex from "knex";
import type { Knex } from "knex"

export async function up(knex: Knex): Promise<void> {
    await knex.schema.createTable("channels", (table) => {
        table.string("channelID").primary();
        table.string("serverID");
        table.string("name");
    });
}

export async function down(knex: Knex): Promise<void> {
    await knex.schema.dropTable("channels");
}
