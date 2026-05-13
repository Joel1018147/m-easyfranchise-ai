/**
 * ╔══════════════════════════════════════════════════════╗
 * ║  M-EasyFranchise AI — Database Layer                ║
 * ║  PostgreSQL schema + query helpers                  ║
 * ╚══════════════════════════════════════════════════════╝
 */

const { Pool } = require('pg');
const crypto   = require('crypto');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ── Query helpers ─────────────────────────────────────────────────────────────
const db = {
  query:  (text, params) => pool.query(text, params),
  getOne: async (text, params) => { const r = await pool.query(text, params); return r.rows[0] || null; },
  getAll: async (text, params) => { const r = await pool.query(text, params); return r.rows; },
  run:    (text, params) => pool.query(text, params),
};

// ── Schema init ───────────────────────────────────────────────────────────────
async function initSchema() {
  const client = await pool.connect();
  try {
    await client.query(`

      -- ── USERS (franchisor staff / admin accounts) ─────────────────────────
      CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        name          VARCHAR(255) NOT NULL,
        email         VARCHAR(255) UNIQUE NOT NULL,
        password      VARCHAR(255),
        avatar        TEXT,
        role          VARCHAR(30)  DEFAULT 'admin',
        api_key       VARCHAR(64)  UNIQUE,
        modus_id      VARCHAR(64),
        created_at    TIMESTAMPTZ  DEFAULT NOW(),
        last_login    TIMESTAMPTZ,
        is_active     BOOLEAN      DEFAULT TRUE
      );

      -- ── FRANCHISE BRANDS ──────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS franchise_brands (
        id              SERIAL PRIMARY KEY,
        owner_id        INTEGER      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name            VARCHAR(255) NOT NULL,
        slug            VARCHAR(100) UNIQUE NOT NULL,
        logo_url        TEXT,
        description     TEXT,
        industry        VARCHAR(100) DEFAULT 'Food & Beverage',
        country         VARCHAR(100) DEFAULT 'Malaysia',
        currency        VARCHAR(10)  DEFAULT 'MYR',
        website         TEXT,
        support_email   TEXT,
        support_phone   TEXT,
        franchise_fee   NUMERIC(12,2),
        royalty_pct     NUMERIC(5,2) DEFAULT 5.00,
        marketing_pct   NUMERIC(5,2) DEFAULT 2.00,
        contract_years  INTEGER      DEFAULT 5,
        status          VARCHAR(20)  DEFAULT 'active',
        ai_summary      TEXT,
        created_at      TIMESTAMPTZ  DEFAULT NOW(),
        updated_at      TIMESTAMPTZ  DEFAULT NOW()
      );

      -- ── FRANCHISE UNITS (branches) ────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS franchise_units (
        id              SERIAL PRIMARY KEY,
        brand_id        INTEGER      NOT NULL REFERENCES franchise_brands(id) ON DELETE CASCADE,
        franchisee_id   INTEGER,
        unit_code       VARCHAR(50)  UNIQUE NOT NULL,
        name            VARCHAR(255) NOT NULL,
        address         TEXT,
        city            VARCHAR(100),
        state           VARCHAR(100),
        postcode        VARCHAR(20),
        country         VARCHAR(100) DEFAULT 'Malaysia',
        lat             NUMERIC(10,7),
        lng             NUMERIC(10,7),
        phone           VARCHAR(50),
        email           TEXT,
        status          VARCHAR(20)  DEFAULT 'active',
        opened_at       DATE,
        contract_start  DATE,
        contract_end    DATE,
        monthly_revenue NUMERIC(12,2) DEFAULT 0,
        ai_health_score INTEGER      DEFAULT 0,
        ai_risk_level   VARCHAR(20)  DEFAULT 'low',
        created_at      TIMESTAMPTZ  DEFAULT NOW(),
        updated_at      TIMESTAMPTZ  DEFAULT NOW()
      );

      -- ── FRANCHISEES (business owners who buy franchise) ───────────────────
      CREATE TABLE IF NOT EXISTS franchisees (
        id              SERIAL PRIMARY KEY,
        brand_id        INTEGER      NOT NULL REFERENCES franchise_brands(id) ON DELETE CASCADE,
        name            VARCHAR(255) NOT NULL,
        email           VARCHAR(255) NOT NULL,
        phone           VARCHAR(50),
        ic_number       VARCHAR(30),
        company_name    VARCHAR(255),
        company_reg     VARCHAR(100),
        address         TEXT,
        city            VARCHAR(100),
        state           VARCHAR(100),
        status          VARCHAR(20)  DEFAULT 'active',
        joined_at       DATE         DEFAULT CURRENT_DATE,
        notes           TEXT,
        ai_score        INTEGER      DEFAULT 0,
        modus_crm_id    VARCHAR(64),
        created_at      TIMESTAMPTZ  DEFAULT NOW(),
        updated_at      TIMESTAMPTZ  DEFAULT NOW()
      );

      -- ── FRANCHISE APPLICATIONS ────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS franchise_applications (
        id              SERIAL PRIMARY KEY,
        brand_id        INTEGER      NOT NULL REFERENCES franchise_brands(id) ON DELETE CASCADE,
        applicant_name  VARCHAR(255) NOT NULL,
        applicant_email VARCHAR(255) NOT NULL,
        applicant_phone VARCHAR(50),
        company_name    VARCHAR(255),
        preferred_city  VARCHAR(100),
        preferred_state VARCHAR(100),
        investment_budget NUMERIC(12,2),
        business_exp    TEXT,
        motivation      TEXT,
        status          VARCHAR(30)  DEFAULT 'new',
        ai_score        INTEGER      DEFAULT 0,
        ai_summary      TEXT,
        reviewed_by     INTEGER      REFERENCES users(id),
        reviewed_at     TIMESTAMPTZ,
        notes           TEXT,
        created_at      TIMESTAMPTZ  DEFAULT NOW(),
        updated_at      TIMESTAMPTZ  DEFAULT NOW()
      );

      -- ── ROYALTY & FINANCIAL REPORTS ───────────────────────────────────────
      CREATE TABLE IF NOT EXISTS royalty_reports (
        id              SERIAL PRIMARY KEY,
        unit_id         INTEGER      NOT NULL REFERENCES franchise_units(id) ON DELETE CASCADE,
        brand_id        INTEGER      NOT NULL REFERENCES franchise_brands(id) ON DELETE CASCADE,
        report_month    DATE         NOT NULL,
        gross_revenue   NUMERIC(12,2) NOT NULL DEFAULT 0,
        royalty_amount  NUMERIC(12,2) NOT NULL DEFAULT 0,
        marketing_fund  NUMERIC(12,2) NOT NULL DEFAULT 0,
        total_due       NUMERIC(12,2) NOT NULL DEFAULT 0,
        status          VARCHAR(20)  DEFAULT 'pending',
        paid_at         TIMESTAMPTZ,
        submitted_at    TIMESTAMPTZ  DEFAULT NOW(),
        notes           TEXT,
        created_at      TIMESTAMPTZ  DEFAULT NOW()
      );

      -- ── COMPLIANCE AUDITS ─────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS compliance_audits (
        id              SERIAL PRIMARY KEY,
        unit_id         INTEGER      NOT NULL REFERENCES franchise_units(id) ON DELETE CASCADE,
        brand_id        INTEGER      NOT NULL REFERENCES franchise_brands(id) ON DELETE CASCADE,
        auditor_id      INTEGER      REFERENCES users(id),
        audit_type      VARCHAR(50)  DEFAULT 'routine',
        audit_date      DATE         NOT NULL,
        overall_score   INTEGER      DEFAULT 0,
        checklist       JSONB        DEFAULT '{}',
        findings        TEXT,
        action_required TEXT,
        status          VARCHAR(20)  DEFAULT 'scheduled',
        ai_summary      TEXT,
        created_at      TIMESTAMPTZ  DEFAULT NOW(),
        updated_at      TIMESTAMPTZ  DEFAULT NOW()
      );

      -- ── SUPPORT TICKETS ───────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS support_tickets (
        id              SERIAL PRIMARY KEY,
        unit_id         INTEGER      REFERENCES franchise_units(id) ON DELETE SET NULL,
        brand_id        INTEGER      NOT NULL REFERENCES franchise_brands(id) ON DELETE CASCADE,
        franchisee_id   INTEGER,
        subject         VARCHAR(500) NOT NULL,
        description     TEXT,
        category        VARCHAR(50)  DEFAULT 'general',
        priority        VARCHAR(20)  DEFAULT 'normal',
        status          VARCHAR(20)  DEFAULT 'open',
        assigned_to     INTEGER      REFERENCES users(id),
        resolved_at     TIMESTAMPTZ,
        ai_suggested_reply TEXT,
        created_at      TIMESTAMPTZ  DEFAULT NOW(),
        updated_at      TIMESTAMPTZ  DEFAULT NOW()
      );

      -- ── TICKET MESSAGES ───────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS ticket_messages (
        id              SERIAL PRIMARY KEY,
        ticket_id       INTEGER      NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
        sender_type     VARCHAR(20)  DEFAULT 'staff',
        sender_name     VARCHAR(255),
        message         TEXT         NOT NULL,
        is_ai           BOOLEAN      DEFAULT FALSE,
        created_at      TIMESTAMPTZ  DEFAULT NOW()
      );

      -- ── TRAINING MODULES ──────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS training_modules (
        id              SERIAL PRIMARY KEY,
        brand_id        INTEGER      NOT NULL REFERENCES franchise_brands(id) ON DELETE CASCADE,
        title           VARCHAR(255) NOT NULL,
        description     TEXT,
        category        VARCHAR(100) DEFAULT 'Operations',
        content_type    VARCHAR(30)  DEFAULT 'document',
        content_url     TEXT,
        duration_mins   INTEGER      DEFAULT 0,
        is_mandatory    BOOLEAN      DEFAULT FALSE,
        order_index     INTEGER      DEFAULT 0,
        created_at      TIMESTAMPTZ  DEFAULT NOW()
      );

      -- ── TRAINING COMPLETIONS ──────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS training_completions (
        id              SERIAL PRIMARY KEY,
        module_id       INTEGER      NOT NULL REFERENCES training_modules(id) ON DELETE CASCADE,
        franchisee_id   INTEGER      NOT NULL REFERENCES franchisees(id) ON DELETE CASCADE,
        unit_id         INTEGER      REFERENCES franchise_units(id),
        completed_at    TIMESTAMPTZ  DEFAULT NOW(),
        score           INTEGER,
        UNIQUE(module_id, franchisee_id)
      );

      -- ── AI ACTIVITY LOG ───────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS ai_activity_log (
        id              SERIAL PRIMARY KEY,
        user_id         INTEGER      REFERENCES users(id),
        action          VARCHAR(100) NOT NULL,
        entity_type     VARCHAR(50),
        entity_id       INTEGER,
        prompt_tokens   INTEGER      DEFAULT 0,
        result_tokens   INTEGER      DEFAULT 0,
        created_at      TIMESTAMPTZ  DEFAULT NOW()
      );

      -- ── AUDIT LOG ─────────────────────────────────────────────────────────
      CREATE TABLE IF NOT EXISTS audit_log (
        id              SERIAL PRIMARY KEY,
        user_id         INTEGER      REFERENCES users(id),
        user_name       VARCHAR(255),
        action          VARCHAR(100) NOT NULL,
        entity          VARCHAR(100),
        entity_id       TEXT,
        detail          TEXT,
        created_at      TIMESTAMPTZ  DEFAULT NOW()
      );

      -- ── INDEXES ───────────────────────────────────────────────────────────
      CREATE INDEX IF NOT EXISTS idx_units_brand       ON franchise_units(brand_id);
      CREATE INDEX IF NOT EXISTS idx_units_franchisee  ON franchise_units(franchisee_id);
      CREATE INDEX IF NOT EXISTS idx_franchisees_brand ON franchisees(brand_id);
      CREATE INDEX IF NOT EXISTS idx_apps_brand        ON franchise_applications(brand_id);
      CREATE INDEX IF NOT EXISTS idx_royalty_unit      ON royalty_reports(unit_id);
      CREATE INDEX IF NOT EXISTS idx_royalty_brand     ON royalty_reports(brand_id);
      CREATE INDEX IF NOT EXISTS idx_audits_unit       ON compliance_audits(unit_id);
      CREATE INDEX IF NOT EXISTS idx_tickets_brand     ON support_tickets(brand_id);
      CREATE INDEX IF NOT EXISTS idx_training_brand    ON training_modules(brand_id);

    `);

    // Add franchisee_id FK to units after franchisees table exists
    await client.query(`
      ALTER TABLE franchise_units
        DROP CONSTRAINT IF EXISTS franchise_units_franchisee_id_fkey;
      ALTER TABLE franchise_units
        ADD CONSTRAINT franchise_units_franchisee_id_fkey
        FOREIGN KEY (franchisee_id) REFERENCES franchisees(id) ON DELETE SET NULL;
    `).catch(() => {}); // ignore if already exists

    // Make first user admin
    await client.query(`
      UPDATE users SET role = 'superadmin'
      WHERE id = (SELECT MIN(id) FROM users) AND role = 'admin'
    `);

    console.log('✓ M-EasyFranchise AI — PostgreSQL schema ready');
  } finally {
    client.release();
  }
}

// ── Audit helper ──────────────────────────────────────────────────────────────
async function logAudit({ userId, userName, action, entity, entityId, detail }) {
  try {
    await db.run(
      `INSERT INTO audit_log (user_id, user_name, action, entity, entity_id, detail)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [userId, userName, action, entity, String(entityId || ''), detail || '']
    );
  } catch (e) {
    console.error('Audit log error:', e.message);
  }
}

module.exports = { pool, db, initSchema, logAudit };
