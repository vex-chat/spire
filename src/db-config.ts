import knex from "knex";
import { test, development } from "./knexfile";

export const db =
    process.env.NODE_ENV === "test" ? knex(test) : knex(development);
