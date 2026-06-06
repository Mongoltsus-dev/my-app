const fs = require("fs");
const path = require("path");
const pg = require("pg");

// Load environment variables from .env.local
require("dotenv").config({ path: path.join(__dirname, "../.env.local") });

const { Pool } = pg;

async function runMigration() {
  if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL environment variable is not set");
    process.exit(1);
  }

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl:
      process.env.DATABASE_URL.includes("sslmode=require") ||
      process.env.DATABASE_URL.includes("neon.tech")
        ? { rejectUnauthorized: false }
        : false,
  });

  try {
    console.log("Starting database migration...");
    console.log("Connecting to database...");

    // Test connection
    await pool.query("SELECT NOW()");
    console.log("Database connection successful\n");

    // Read all migration files sorted by name
    const migrationsDir = path.join(__dirname, "../database/migrations");
    
    if (!fs.existsSync(migrationsDir)) {
      console.error("Migrations directory not found:", migrationsDir);
      process.exit(1);
    }

    const files = fs
      .readdirSync(migrationsDir)
      .filter((f) => f.endsWith(".sql"))
      .sort();

    if (files.length === 0) {
      console.log("No migration files found.");
      process.exit(0);
    }

    console.log(`Found ${files.length} migration file(s):\n`);

    for (const file of files) {
      const filePath = path.join(migrationsDir, file);
      const sql = fs.readFileSync(filePath, "utf-8");

      console.log(`Running: ${file}`);
      await pool.query(sql);
      console.log(`${file} completed`);
    }

    console.log("\n All migrations completed successfully!");
    process.exit(0);
  } catch (error) {
    console.error("\n Migration failed:");
    console.error("Error:", error.message);
    if (error.detail) console.error("Detail:", error.detail);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

runMigration();
