import * as Knex from "knex";

export async function up(knex: Knex): Promise<void> {
    await knex.schema.createTable("oneTimeKeys", (table) => {
        table.string("keyID").primary();
        table.string("userID").index();
        table.string("publicKey");
        table.string("signature");
        table.integer("index");
    });
}

export async function down(knex: Knex): Promise<void> {
    await knex.schema.dropTable("oneTimeKeys");
}
