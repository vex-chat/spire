// import * as Knex from "knex";
import type { Knex } from "knex"

export async function up(knex: Knex): Promise<void> {
    await knex.schema.createTable("preKeys", (table) => {
        table.string("keyID").primary();
        table.string("userID").index();
        table.string("publicKey");
        table.string("signature");
        table.integer("index");
    });
}

export async function down(knex: Knex): Promise<void> {
    await knex.schema.dropTable("preKeys");
}
