import * as Knex from "knex";

export async function up(knex: Knex): Promise<void> {
    await knex.schema.createTable("users", (table) => {
        table.string("userID").primary();
        table.string("signKey").unique();
        table.string("username").unique();
        table.string("avatar");
        table.dateTime("lastSeen");
    });
}

export async function down(knex: Knex): Promise<void> {
    await knex.schema.dropTable("users");
}
