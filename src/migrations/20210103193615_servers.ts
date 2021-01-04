import * as Knex from "knex";

export async function up(knex: Knex): Promise<void> {
    await knex.schema.createTable("servers", (table) => {
        table.string("serverID").primary();
        table.string("name");
        table.string("icon");
    });
}

export async function down(knex: Knex): Promise<void> {
    await knex.schema.dropTable("servers");
}
