/**
 * DDrive 1.0 virtual filesystem (historical, retained as a no-op).
 *
 * This migration created `directory` + `block` for the original flat VFS, which
 * the 2.0 rewrite replaced with the bucket/object model. It is kept in the
 * migration directory, with an empty body, purely so that databases which
 * already applied it are not reported by knex as a corrupt migration directory
 * ("the following files are missing").
 *
 * - Fresh deployments: this file does nothing; the 2.0 baseline migration
 *   (20260101000000_2.0.0_baseline.js) creates the complete schema.
 * - Existing 1.0 deployments: the baseline migration detects the legacy
 *   `directory`/`block` tables, copies their rows into `legacy_directory` /
 *   `legacy_block` and only then drops the originals.
 *
 * The original body is in git history (see the commit that introduced this
 * comment); the archived shapes it created are mirrored in the baseline
 * migration's LEGACY_TABLES list.
 */
exports.up = async () => {}

// Never destructive on rollback: whether a database still holds 1.0 tables is
// decided by the baseline migration, which owns the schema from here on.
exports.down = async () => {}
