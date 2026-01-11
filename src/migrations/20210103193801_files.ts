// import * as Knex from "knex";
import type { Knex } from "knex"

export async function up(knex: Knex): Promise<void> {
    await knex.schema.createTable("files", (table) => {
        table.string("fileID").primary();
        table.string("owner").index();
        table.string("nonce");
    });
}

export async function down(knex: Knex): Promise<void> {
    await knex.schema.dropTable("files");
}
