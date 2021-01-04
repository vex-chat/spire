import * as Knex from "knex";

export async function up(knex: Knex): Promise<void> {
    await knex.schema.createTable("mail", (table) => {
        table.string("nonce").primary();
        table.string("recipient").index();
        table.string("mailID");
        table.string("sender");
        table.string("header");
        table.text("cipher", "mediumtext");
        table.string("group");
        table.text("extra");
        table.integer("mailType");
        table.dateTime("time");
    });
}

export async function down(knex: Knex): Promise<void> {
    await knex.schema.dropTable("mail");
}
