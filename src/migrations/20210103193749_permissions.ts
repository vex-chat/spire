import * as Knex from "knex";

export async function up(knex: Knex): Promise<void> {
    await knex.schema.createTable("permissions", (table) => {
        table.string("permissionID").primary();
        table.string("userID").index();
        table.string("resourceType");
        table.string("resourceID").index();
        table.integer("powerLevel");
    });
}

export async function down(knex: Knex): Promise<void> {
    await knex.schema.dropTable("permissions");
}
