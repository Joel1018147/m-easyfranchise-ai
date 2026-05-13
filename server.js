/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  M-EasyFranchise AI — Production Server v1.0               ║
 * ║  Franchise Management Platform — MODUS AI Ecosystem        ║
 * ║  PostgreSQL + Claude AI + JWT Auth                         ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const path       = require('path');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const rateLimit  = require('express-rate-limit');
const helmet     = require('helmet');
const crypto     = require('crypto');
const { db, initSchema, logAudit } = require('./db');
const { OAuth2Client } = require('google-auth-library');

const app     = express();
const PORT    = process.env.PORT || 3002;
const JWT_SECRET    = process.env.JWT_SECRET || 'mef-dev-secret-change-this';
const GROQ_KEY = process.env.GROQ_API_KEY;
const APP_URL       = process.env.APP_URL || `http://localhost:${PORT}`;
const IS_PROD       = process.env.NODE_ENV === 'production';
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// ── Init DB ────────────────────────────────────────────────────────────────────
initSchema().catch(err => console.error('✗ DB init failed:', err.message));

// ── Middleware ─────────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

if (IS_PROD) {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https')
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    next();
  });
}

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30,  message: { error: 'Too many attempts.' } });
const apiLimiter  = rateLimit({ windowMs: 60 * 1000,      max: 120, message: { error: 'Too many requests.' } });

// ── Auth helpers ───────────────────────────────────────────────────────────────
function makeToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
}

function safeUser(u) {
  return {
    id: u.id, name: u.name, email: u.email,
    role: u.role, avatar: u.avatar, api_key: u.api_key,
    modus_id: u.modus_id,
  };
}

async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer '))
    return res.status(401).json({ error: 'Please log in' });
  try {
    const { userId } = jwt.verify(auth.slice(7), JWT_SECRET);
    const user = await db.getOne(
      'SELECT * FROM users WHERE id = $1 AND is_active = TRUE', [userId]
    );
    if (!user) return res.status(401).json({ error: 'Account not found' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired' });
  }
}

async function requireAdmin(req, res, next) {
  if (!['admin', 'superadmin'].includes(req.user?.role))
    return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ── Claude AI helper ───────────────────────────────────────────────────────────
async function callGroq(systemPrompt, userMessage, maxTokens = 1000) {
  if (!GROQ_KEY) throw new Error('GROQ_API_KEY not configured');
  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': 'Bearer ' + GROQ_KEY,
    },
    body: JSON.stringify({
      model:       'llama-3.3-70b-versatile',
      max_tokens:  maxTokens,
      temperature: 0.7,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user',   content: userMessage },
      ],
    }),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error?.message || 'Groq API error');
  return data.choices[0].message.content;
}

// ── Log AI usage ───────────────────────────────────────────────────────────────
async function logAI(userId, action, entityType = null, entityId = null) {
  await db.run(
    `INSERT INTO ai_activity_log (user_id, action, entity_type, entity_id)
     VALUES ($1, $2, $3, $4)`,
    [userId, action, entityType, entityId]
  ).catch(() => {});
}

// ════════════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════════════════════

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name?.trim() || !email?.trim() || !password)
      return res.status(400).json({ error: 'All fields required' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Invalid email address' });
    if (await db.getOne('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]))
      return res.status(409).json({ error: 'Email already registered' });

    const hash   = await bcrypt.hash(password, 12);
    const apiKey = crypto.randomBytes(32).toString('hex');
    const isFirst = !(await db.getOne('SELECT id FROM users LIMIT 1'));
    const user = await db.getOne(
      `INSERT INTO users (name, email, password, api_key, role)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [name.trim(), email.toLowerCase(), hash, apiKey, isFirst ? 'superadmin' : 'admin']
    );
    res.status(201).json({ token: makeToken(user.id), user: safeUser(user) });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed: ' + err.message });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });
    const user = await db.getOne(
      'SELECT * FROM users WHERE email = $1 AND is_active = TRUE', [email.toLowerCase()]
    );
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: 'Invalid email or password' });
    await db.run('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    res.json({ token: makeToken(user.id), user: safeUser(user) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', requireAuth, (req, res) => res.json(safeUser(req.user)));

app.put('/api/auth/me', requireAuth, async (req, res) => {
  const { name } = req.body;
  const user = await db.getOne(
    'UPDATE users SET name = COALESCE($1, name) WHERE id = $2 RETURNING *',
    [name, req.user.id]
  );
  res.json({ success: true, user: safeUser(user) });
});

app.put('/api/auth/password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword)
    return res.status(400).json({ error: 'Both passwords required' });
  if (newPassword.length < 8)
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  const user = await db.getOne('SELECT * FROM users WHERE id = $1', [req.user.id]);
  if (!(await bcrypt.compare(currentPassword, user.password)))
    return res.status(401).json({ error: 'Current password incorrect' });
  const hash = await bcrypt.hash(newPassword, 12);
  await db.run('UPDATE users SET password = $1 WHERE id = $2', [hash, req.user.id]);
  res.json({ success: true });
});

// ── Google OAuth ───────────────────────────────────────────────────────────────
app.get('/api/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.status(500).json({ error: 'Google OAuth not configured' });
  const params = new URLSearchParams({
    client_id:     GOOGLE_CLIENT_ID,
    redirect_uri:  `${APP_URL}/api/auth/google/callback`,
    response_type: 'code',
    scope:         'openid email profile',
    access_type:   'offline',
    prompt:        'select_account',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.redirect('/login.html?error=no_code');

    // Exchange code for tokens
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id:     GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri:  `${APP_URL}/api/auth/google/callback`,
        grant_type:    'authorization_code',
      }),
    });
    const tokens = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(tokens.error_description || 'Token exchange failed');

    // Verify ID token
    const ticket = await googleClient.verifyIdToken({
      idToken:  tokens.id_token,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { email, name, picture, sub: googleId } = payload;

    // Find or create user
    let user = await db.getOne('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (!user) {
      const isFirst = !(await db.getOne('SELECT id FROM users LIMIT 1'));
      const apiKey  = crypto.randomBytes(32).toString('hex');
      user = await db.getOne(
        `INSERT INTO users (name, email, avatar, api_key, role, modus_id)
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
        [name, email.toLowerCase(), picture, apiKey,
         isFirst ? 'superadmin' : 'admin', googleId]
      );
    } else {
      // Update avatar and last login
      user = await db.getOne(
        `UPDATE users SET avatar = COALESCE($1, avatar), last_login = NOW()
         WHERE id = $2 RETURNING *`,
        [picture, user.id]
      );
    }

    if (!user.is_active) return res.redirect('/login.html?error=account_disabled');

    const token = makeToken(user.id);
    // Redirect to app with token
    res.redirect(`/app.html?token=${token}&user=${encodeURIComponent(JSON.stringify(safeUser(user)))}`);
  } catch (err) {
    console.error('Google OAuth error:', err.message);
    res.redirect('/login.html?error=oauth_failed');
  }
});

// ════════════════════════════════════════════════════════════════════════
//  FRANCHISE BRANDS
// ════════════════════════════════════════════════════════════════════════

app.get('/api/brands', requireAuth, async (req, res) => {
  try {
    const brands = await db.getAll(
      `SELECT fb.*,
         (SELECT COUNT(*) FROM franchise_units fu WHERE fu.brand_id = fb.id) AS unit_count,
         (SELECT COUNT(*) FROM franchisees f WHERE f.brand_id = fb.id) AS franchisee_count,
         (SELECT COUNT(*) FROM franchise_applications fa WHERE fa.brand_id = fb.id AND fa.status = 'new') AS pending_apps
       FROM franchise_brands fb
       WHERE fb.owner_id = $1
       ORDER BY fb.created_at DESC`,
      [req.user.id]
    );
    res.json(brands);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/brands', requireAuth, async (req, res) => {
  try {
    const {
      name, description, industry, country, currency,
      website, support_email, support_phone,
      franchise_fee, royalty_pct, marketing_pct, contract_years
    } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Brand name required' });

    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
               + '-' + crypto.randomBytes(3).toString('hex');

    const brand = await db.getOne(
      `INSERT INTO franchise_brands
         (owner_id, name, slug, description, industry, country, currency,
          website, support_email, support_phone,
          franchise_fee, royalty_pct, marketing_pct, contract_years)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [req.user.id, name.trim(), slug, description, industry || 'Food & Beverage',
       country || 'Malaysia', currency || 'MYR',
       website, support_email, support_phone,
       franchise_fee || 0, royalty_pct || 5, marketing_pct || 2, contract_years || 5]
    );
    await logAudit({ userId: req.user.id, userName: req.user.name, action: 'Created', entity: 'Brand', entityId: brand.id, detail: brand.name });
    res.status(201).json(brand);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/brands/:id', requireAuth, async (req, res) => {
  try {
    const brand = await db.getOne(
      'SELECT * FROM franchise_brands WHERE id = $1 AND owner_id = $2',
      [req.params.id, req.user.id]
    );
    if (!brand) return res.status(404).json({ error: 'Brand not found' });
    res.json(brand);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/brands/:id', requireAuth, async (req, res) => {
  try {
    const {
      name, description, industry, country, currency, website,
      support_email, support_phone, franchise_fee,
      royalty_pct, marketing_pct, contract_years, status
    } = req.body;
    const brand = await db.getOne(
      `UPDATE franchise_brands SET
         name = COALESCE($1, name), description = COALESCE($2, description),
         industry = COALESCE($3, industry), country = COALESCE($4, country),
         currency = COALESCE($5, currency), website = COALESCE($6, website),
         support_email = COALESCE($7, support_email), support_phone = COALESCE($8, support_phone),
         franchise_fee = COALESCE($9, franchise_fee), royalty_pct = COALESCE($10, royalty_pct),
         marketing_pct = COALESCE($11, marketing_pct), contract_years = COALESCE($12, contract_years),
         status = COALESCE($13, status), updated_at = NOW()
       WHERE id = $14 AND owner_id = $15 RETURNING *`,
      [name, description, industry, country, currency, website,
       support_email, support_phone, franchise_fee,
       royalty_pct, marketing_pct, contract_years, status,
       req.params.id, req.user.id]
    );
    if (!brand) return res.status(404).json({ error: 'Brand not found' });
    await logAudit({ userId: req.user.id, userName: req.user.name, action: 'Updated', entity: 'Brand', entityId: brand.id, detail: brand.name });
    res.json(brand);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════
//  FRANCHISE UNITS
// ════════════════════════════════════════════════════════════════════════

app.get('/api/brands/:brandId/units', requireAuth, async (req, res) => {
  try {
    const units = await db.getAll(
      `SELECT fu.*, f.name AS franchisee_name, f.email AS franchisee_email
       FROM franchise_units fu
       LEFT JOIN franchisees f ON f.id = fu.franchisee_id
       WHERE fu.brand_id = $1
       ORDER BY fu.created_at DESC`,
      [req.params.brandId]
    );
    res.json(units);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/brands/:brandId/units', requireAuth, async (req, res) => {
  try {
    const {
      name, franchisee_id, unit_code,
      address, city, state, postcode, country,
      phone, email, opened_at, contract_start, contract_end
    } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Unit name required' });

    const code = unit_code || `U-${Date.now().toString(36).toUpperCase()}`;
    const unit = await db.getOne(
      `INSERT INTO franchise_units
         (brand_id, franchisee_id, unit_code, name,
          address, city, state, postcode, country,
          phone, email, opened_at, contract_start, contract_end)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [req.params.brandId, franchisee_id || null, code, name.trim(),
       address, city, state, postcode, country || 'Malaysia',
       phone, email, opened_at || null, contract_start || null, contract_end || null]
    );
    await logAudit({ userId: req.user.id, userName: req.user.name, action: 'Created', entity: 'Unit', entityId: unit.id, detail: unit.name });
    res.status(201).json(unit);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/units/:id', requireAuth, async (req, res) => {
  try {
    const {
      name, franchisee_id, address, city, state, postcode,
      phone, email, status, monthly_revenue,
      contract_start, contract_end, opened_at
    } = req.body;
    const unit = await db.getOne(
      `UPDATE franchise_units SET
         name = COALESCE($1, name), franchisee_id = COALESCE($2, franchisee_id),
         address = COALESCE($3, address), city = COALESCE($4, city),
         state = COALESCE($5, state), postcode = COALESCE($6, postcode),
         phone = COALESCE($7, phone), email = COALESCE($8, email),
         status = COALESCE($9, status), monthly_revenue = COALESCE($10, monthly_revenue),
         contract_start = COALESCE($11, contract_start), contract_end = COALESCE($12, contract_end),
         opened_at = COALESCE($13, opened_at), updated_at = NOW()
       WHERE id = $14 RETURNING *`,
      [name, franchisee_id, address, city, state, postcode,
       phone, email, status, monthly_revenue,
       contract_start, contract_end, opened_at, req.params.id]
    );
    if (!unit) return res.status(404).json({ error: 'Unit not found' });
    res.json(unit);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════
//  FRANCHISEES
// ════════════════════════════════════════════════════════════════════════

app.get('/api/brands/:brandId/franchisees', requireAuth, async (req, res) => {
  try {
    const franchisees = await db.getAll(
      `SELECT f.*,
         (SELECT COUNT(*) FROM franchise_units fu WHERE fu.franchisee_id = f.id) AS unit_count
       FROM franchisees f
       WHERE f.brand_id = $1
       ORDER BY f.created_at DESC`,
      [req.params.brandId]
    );
    res.json(franchisees);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/brands/:brandId/franchisees', requireAuth, async (req, res) => {
  try {
    const {
      name, email, phone, ic_number,
      company_name, company_reg, address, city, state, notes
    } = req.body;
    if (!name?.trim() || !email?.trim())
      return res.status(400).json({ error: 'Name and email required' });

    const franchisee = await db.getOne(
      `INSERT INTO franchisees
         (brand_id, name, email, phone, ic_number,
          company_name, company_reg, address, city, state, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [req.params.brandId, name.trim(), email.toLowerCase(), phone,
       ic_number, company_name, company_reg, address, city, state, notes]
    );
    await logAudit({ userId: req.user.id, userName: req.user.name, action: 'Created', entity: 'Franchisee', entityId: franchisee.id, detail: franchisee.name });
    res.status(201).json(franchisee);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/franchisees/:id', requireAuth, async (req, res) => {
  try {
    const {
      name, email, phone, ic_number,
      company_name, company_reg, address, city, state,
      status, notes
    } = req.body;
    const franchisee = await db.getOne(
      `UPDATE franchisees SET
         name = COALESCE($1, name), email = COALESCE($2, email),
         phone = COALESCE($3, phone), ic_number = COALESCE($4, ic_number),
         company_name = COALESCE($5, company_name), company_reg = COALESCE($6, company_reg),
         address = COALESCE($7, address), city = COALESCE($8, city),
         state = COALESCE($9, state), status = COALESCE($10, status),
         notes = COALESCE($11, notes), updated_at = NOW()
       WHERE id = $12 RETURNING *`,
      [name, email, phone, ic_number, company_name, company_reg,
       address, city, state, status, notes, req.params.id]
    );
    if (!franchisee) return res.status(404).json({ error: 'Franchisee not found' });
    res.json(franchisee);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════
//  APPLICATIONS
// ════════════════════════════════════════════════════════════════════════

app.get('/api/brands/:brandId/applications', requireAuth, async (req, res) => {
  try {
    const apps = await db.getAll(
      `SELECT * FROM franchise_applications
       WHERE brand_id = $1 ORDER BY created_at DESC`,
      [req.params.brandId]
    );
    res.json(apps);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Public: applicant submits form
app.post('/api/apply/:brandSlug', async (req, res) => {
  try {
    const brand = await db.getOne(
      'SELECT * FROM franchise_brands WHERE slug = $1 AND status = $2',
      [req.params.brandSlug, 'active']
    );
    if (!brand) return res.status(404).json({ error: 'Franchise not found' });

    const {
      applicant_name, applicant_email, applicant_phone,
      company_name, preferred_city, preferred_state,
      investment_budget, business_exp, motivation
    } = req.body;

    if (!applicant_name?.trim() || !applicant_email?.trim())
      return res.status(400).json({ error: 'Name and email required' });

    const app_ = await db.getOne(
      `INSERT INTO franchise_applications
         (brand_id, applicant_name, applicant_email, applicant_phone,
          company_name, preferred_city, preferred_state,
          investment_budget, business_exp, motivation)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [brand.id, applicant_name.trim(), applicant_email.toLowerCase(),
       applicant_phone, company_name,
       preferred_city, preferred_state,
       investment_budget || null, business_exp, motivation]
    );
    res.status(201).json({ success: true, id: app_.id, message: 'Application submitted successfully' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/applications/:id', requireAuth, async (req, res) => {
  try {
    const { status, notes } = req.body;
    const app_ = await db.getOne(
      `UPDATE franchise_applications SET
         status = COALESCE($1, status),
         notes = COALESCE($2, notes),
         reviewed_by = $3,
         reviewed_at = NOW(),
         updated_at = NOW()
       WHERE id = $4 RETURNING *`,
      [status, notes, req.user.id, req.params.id]
    );
    if (!app_) return res.status(404).json({ error: 'Application not found' });
    await logAudit({ userId: req.user.id, userName: req.user.name, action: 'Updated', entity: 'Application', entityId: app_.id, detail: `Status: ${status}` });
    res.json(app_);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════
//  ROYALTY REPORTS
// ════════════════════════════════════════════════════════════════════════

app.get('/api/brands/:brandId/royalties', requireAuth, async (req, res) => {
  try {
    const reports = await db.getAll(
      `SELECT rr.*, fu.name AS unit_name, fu.unit_code
       FROM royalty_reports rr
       JOIN franchise_units fu ON fu.id = rr.unit_id
       WHERE rr.brand_id = $1
       ORDER BY rr.report_month DESC, rr.created_at DESC`,
      [req.params.brandId]
    );
    res.json(reports);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/brands/:brandId/royalties', requireAuth, async (req, res) => {
  try {
    const { unit_id, report_month, gross_revenue, notes } = req.body;
    if (!unit_id || !report_month || gross_revenue === undefined)
      return res.status(400).json({ error: 'unit_id, report_month, gross_revenue required' });

    const brand = await db.getOne(
      'SELECT * FROM franchise_brands WHERE id = $1', [req.params.brandId]
    );
    const royalty_amount  = (gross_revenue * brand.royalty_pct  / 100).toFixed(2);
    const marketing_fund  = (gross_revenue * brand.marketing_pct / 100).toFixed(2);
    const total_due       = (parseFloat(royalty_amount) + parseFloat(marketing_fund)).toFixed(2);

    const report = await db.getOne(
      `INSERT INTO royalty_reports
         (unit_id, brand_id, report_month, gross_revenue,
          royalty_amount, marketing_fund, total_due, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [unit_id, req.params.brandId, report_month, gross_revenue,
       royalty_amount, marketing_fund, total_due, notes]
    );
    res.status(201).json(report);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/royalties/:id/pay', requireAuth, async (req, res) => {
  try {
    const report = await db.getOne(
      `UPDATE royalty_reports SET status = 'paid', paid_at = NOW()
       WHERE id = $1 RETURNING *`,
      [req.params.id]
    );
    if (!report) return res.status(404).json({ error: 'Report not found' });
    res.json(report);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════
//  COMPLIANCE AUDITS
// ════════════════════════════════════════════════════════════════════════

app.get('/api/brands/:brandId/audits', requireAuth, async (req, res) => {
  try {
    const audits = await db.getAll(
      `SELECT ca.*, fu.name AS unit_name, fu.unit_code
       FROM compliance_audits ca
       JOIN franchise_units fu ON fu.id = ca.unit_id
       WHERE ca.brand_id = $1
       ORDER BY ca.audit_date DESC`,
      [req.params.brandId]
    );
    res.json(audits);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/brands/:brandId/audits', requireAuth, async (req, res) => {
  try {
    const {
      unit_id, audit_type, audit_date, overall_score,
      checklist, findings, action_required
    } = req.body;
    if (!unit_id || !audit_date)
      return res.status(400).json({ error: 'unit_id and audit_date required' });

    const audit = await db.getOne(
      `INSERT INTO compliance_audits
         (unit_id, brand_id, auditor_id, audit_type, audit_date,
          overall_score, checklist, findings, action_required, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'completed') RETURNING *`,
      [unit_id, req.params.brandId, req.user.id, audit_type || 'routine',
       audit_date, overall_score || 0,
       JSON.stringify(checklist || {}), findings, action_required]
    );

    // Update unit health score
    await db.run(
      `UPDATE franchise_units SET ai_health_score = $1,
         ai_risk_level = CASE WHEN $1 >= 80 THEN 'low'
                              WHEN $1 >= 60 THEN 'medium' ELSE 'high' END
       WHERE id = $2`,
      [overall_score || 0, unit_id]
    );

    res.status(201).json(audit);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════
//  SUPPORT TICKETS
// ════════════════════════════════════════════════════════════════════════

app.get('/api/brands/:brandId/tickets', requireAuth, async (req, res) => {
  try {
    const tickets = await db.getAll(
      `SELECT st.*, fu.name AS unit_name, f.name AS franchisee_name
       FROM support_tickets st
       LEFT JOIN franchise_units fu ON fu.id = st.unit_id
       LEFT JOIN franchisees f ON f.id = st.franchisee_id
       WHERE st.brand_id = $1
       ORDER BY
         CASE st.priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2
                          WHEN 'normal' THEN 3 ELSE 4 END,
         st.created_at DESC`,
      [req.params.brandId]
    );
    res.json(tickets);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/brands/:brandId/tickets', requireAuth, async (req, res) => {
  try {
    const {
      unit_id, franchisee_id, subject, description,
      category, priority
    } = req.body;
    if (!subject?.trim()) return res.status(400).json({ error: 'Subject required' });

    const ticket = await db.getOne(
      `INSERT INTO support_tickets
         (brand_id, unit_id, franchisee_id, subject, description, category, priority)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [req.params.brandId, unit_id || null, franchisee_id || null,
       subject.trim(), description, category || 'general', priority || 'normal']
    );
    res.status(201).json(ticket);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/tickets/:id', requireAuth, async (req, res) => {
  try {
    const { status, assigned_to, priority } = req.body;
    const ticket = await db.getOne(
      `UPDATE support_tickets SET
         status = COALESCE($1, status),
         assigned_to = COALESCE($2, assigned_to),
         priority = COALESCE($3, priority),
         resolved_at = CASE WHEN $1 = 'resolved' THEN NOW() ELSE resolved_at END,
         updated_at = NOW()
       WHERE id = $4 RETURNING *`,
      [status, assigned_to, priority, req.params.id]
    );
    res.json(ticket);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/tickets/:id/messages', requireAuth, async (req, res) => {
  try {
    const messages = await db.getAll(
      'SELECT * FROM ticket_messages WHERE ticket_id = $1 ORDER BY created_at ASC',
      [req.params.id]
    );
    res.json(messages);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/tickets/:id/messages', requireAuth, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message?.trim()) return res.status(400).json({ error: 'Message required' });
    const msg = await db.getOne(
      `INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, message)
       VALUES ($1,'staff',$2,$3) RETURNING *`,
      [req.params.id, req.user.name, message.trim()]
    );
    await db.run(
      `UPDATE support_tickets SET status = 'in_progress', updated_at = NOW()
       WHERE id = $1 AND status = 'open'`,
      [req.params.id]
    );
    res.status(201).json(msg);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════
//  TRAINING
// ════════════════════════════════════════════════════════════════════════

app.get('/api/brands/:brandId/training', requireAuth, async (req, res) => {
  try {
    const modules = await db.getAll(
      `SELECT tm.*,
         (SELECT COUNT(*) FROM training_completions tc WHERE tc.module_id = tm.id) AS completion_count
       FROM training_modules tm
       WHERE tm.brand_id = $1 ORDER BY tm.order_index, tm.created_at`,
      [req.params.brandId]
    );
    res.json(modules);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/brands/:brandId/training', requireAuth, async (req, res) => {
  try {
    const {
      title, description, category, content_type,
      content_url, duration_mins, is_mandatory
    } = req.body;
    if (!title?.trim()) return res.status(400).json({ error: 'Title required' });

    const mod = await db.getOne(
      `INSERT INTO training_modules
         (brand_id, title, description, category, content_type,
          content_url, duration_mins, is_mandatory)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [req.params.brandId, title.trim(), description,
       category || 'Operations', content_type || 'document',
       content_url, duration_mins || 0, is_mandatory || false]
    );
    res.status(201).json(mod);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════
//  ANALYTICS DASHBOARD
// ════════════════════════════════════════════════════════════════════════

app.get('/api/brands/:brandId/analytics', requireAuth, async (req, res) => {
  try {
    const brandId = req.params.brandId;

    const [units, franchisees, apps, royalties, tickets, audits] = await Promise.all([
      db.getOne(`SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active,
                   SUM(monthly_revenue) AS total_monthly_revenue,
                   AVG(ai_health_score) AS avg_health
                 FROM franchise_units WHERE brand_id = $1`, [brandId]),
      db.getOne(`SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active
                 FROM franchisees WHERE brand_id = $1`, [brandId]),
      db.getOne(`SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status='new' THEN 1 ELSE 0 END) AS pending
                 FROM franchise_applications WHERE brand_id = $1`, [brandId]),
      db.getOne(`SELECT SUM(gross_revenue) AS total_revenue,
                   SUM(royalty_amount) AS total_royalty,
                   SUM(total_due) AS total_due,
                   SUM(CASE WHEN status='pending' THEN total_due ELSE 0 END) AS outstanding
                 FROM royalty_reports WHERE brand_id = $1`, [brandId]),
      db.getOne(`SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) AS open_count,
                   SUM(CASE WHEN status='resolved' THEN 1 ELSE 0 END) AS resolved
                 FROM support_tickets WHERE brand_id = $1`, [brandId]),
      db.getOne(`SELECT AVG(overall_score) AS avg_score,
                   SUM(CASE WHEN overall_score < 60 THEN 1 ELSE 0 END) AS failing
                 FROM compliance_audits WHERE brand_id = $1`, [brandId]),
    ]);

    // Revenue last 6 months
    const monthlyRevenue = await db.getAll(
      `SELECT DATE_TRUNC('month', report_month) AS month,
              SUM(gross_revenue) AS revenue, SUM(royalty_amount) AS royalty
       FROM royalty_reports WHERE brand_id = $1
         AND report_month >= NOW() - INTERVAL '6 months'
       GROUP BY 1 ORDER BY 1`,
      [brandId]
    );

    // Units by status
    const unitsByStatus = await db.getAll(
      `SELECT status, COUNT(*) AS count FROM franchise_units
       WHERE brand_id = $1 GROUP BY status`, [brandId]
    );

    res.json({
      units, franchisees, apps, royalties, tickets, audits,
      monthlyRevenue, unitsByStatus,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════
//  AI ROUTES (Claude)
// ════════════════════════════════════════════════════════════════════════

// AI: Score a franchise application
app.post('/api/ai/score-application/:id', requireAuth, apiLimiter, async (req, res) => {
  try {
    const app_ = await db.getOne(
      'SELECT * FROM franchise_applications WHERE id = $1', [req.params.id]
    );
    if (!app_) return res.status(404).json({ error: 'Application not found' });

    const brand = await db.getOne(
      'SELECT * FROM franchise_brands WHERE id = $1', [app_.brand_id]
    );

    const systemPrompt = `You are M-EasyFranchise AI, an expert franchise business analyst. 
Evaluate franchise applications objectively and provide structured scoring.
Always respond with valid JSON only. No markdown, no preamble.`;

    const userMessage = `Evaluate this franchise application for ${brand.name}:
Applicant: ${app_.applicant_name}
Location: ${app_.preferred_city}, ${app_.preferred_state}
Investment Budget: ${brand.currency} ${app_.investment_budget || 'Not stated'}
Business Experience: ${app_.business_exp || 'Not provided'}
Motivation: ${app_.motivation || 'Not provided'}
Franchise Fee Required: ${brand.currency} ${brand.franchise_fee}

Return JSON: { "score": 0-100, "recommendation": "approve|review|reject", "summary": "2-3 sentence assessment", "strengths": ["..."], "concerns": ["..."] }`;

    const result = await callGroq(systemPrompt, userMessage, 800);
    const parsed = JSON.parse(result.replace(/```json|```/g, '').trim());

    await db.run(
      `UPDATE franchise_applications SET ai_score = $1, ai_summary = $2 WHERE id = $3`,
      [parsed.score, parsed.summary, req.params.id]
    );

    await logAI(req.user.id, 'score_application', 'application', req.params.id);
    res.json(parsed);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// AI: Generate franchise brand overview
app.post('/api/ai/brand-overview/:id', requireAuth, apiLimiter, async (req, res) => {
  try {
    const brand = await db.getOne(
      'SELECT * FROM franchise_brands WHERE id = $1 AND owner_id = $2',
      [req.params.id, req.user.id]
    );
    if (!brand) return res.status(404).json({ error: 'Brand not found' });

    const analytics = await db.getOne(
      `SELECT COUNT(*) AS units,
         SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active_units
       FROM franchise_units WHERE brand_id = $1`, [req.params.id]
    );

    const systemPrompt = `You are M-EasyFranchise AI. Generate concise, professional franchise brand intelligence summaries. Be specific and data-driven.`;

    const userMessage = `Generate a professional 3-paragraph executive summary for this franchise brand:
Name: ${brand.name}
Industry: ${brand.industry}
Country: ${brand.country}
Description: ${brand.description || 'N/A'}
Total Units: ${analytics.units}
Active Units: ${analytics.active_units}
Royalty: ${brand.royalty_pct}% | Marketing Fund: ${brand.marketing_pct}%
Contract Length: ${brand.contract_years} years
Franchise Fee: ${brand.currency} ${brand.franchise_fee}

Paragraph 1: Brand overview and market position.
Paragraph 2: Financial model and franchisee opportunity.
Paragraph 3: Growth outlook and key strengths.`;

    const summary = await callGroq(systemPrompt, userMessage, 600);
    await db.run(
      'UPDATE franchise_brands SET ai_summary = $1, updated_at = NOW() WHERE id = $2',
      [summary, req.params.id]
    );
    await logAI(req.user.id, 'brand_overview', 'brand', req.params.id);
    res.json({ summary });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// AI: Generate ticket suggested reply
app.post('/api/ai/ticket-reply/:id', requireAuth, apiLimiter, async (req, res) => {
  try {
    const ticket = await db.getOne(
      'SELECT * FROM support_tickets WHERE id = $1', [req.params.id]
    );
    if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

    const brand = await db.getOne(
      'SELECT name FROM franchise_brands WHERE id = $1', [ticket.brand_id]
    );

    const messages = await db.getAll(
      'SELECT * FROM ticket_messages WHERE ticket_id = $1 ORDER BY created_at ASC',
      [req.params.id]
    );
    const thread = messages.map(m => `[${m.sender_type}]: ${m.message}`).join('\n');

    const systemPrompt = `You are the franchise support AI for ${brand.name}. Write professional, helpful, empathetic support replies. Be concise and solution-focused.`;

    const userMessage = `Support ticket #${ticket.id}
Subject: ${ticket.subject}
Category: ${ticket.category}
Priority: ${ticket.priority}
Description: ${ticket.description || 'N/A'}
${thread ? `\nConversation so far:\n${thread}` : ''}

Write a professional support reply that addresses the franchisee's concern.`;

    const reply = await callGroq(systemPrompt, userMessage, 500);
    await db.run(
      'UPDATE support_tickets SET ai_suggested_reply = $1 WHERE id = $2',
      [reply, req.params.id]
    );
    await logAI(req.user.id, 'ticket_reply', 'ticket', req.params.id);
    res.json({ reply });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// AI: Analyze unit performance
app.post('/api/ai/unit-analysis/:id', requireAuth, apiLimiter, async (req, res) => {
  try {
    const unit = await db.getOne(
      `SELECT fu.*, fb.name AS brand_name, fb.currency, fb.royalty_pct,
         f.name AS franchisee_name
       FROM franchise_units fu
       JOIN franchise_brands fb ON fb.id = fu.brand_id
       LEFT JOIN franchisees f ON f.id = fu.franchisee_id
       WHERE fu.id = $1`, [req.params.id]
    );
    if (!unit) return res.status(404).json({ error: 'Unit not found' });

    const royalties = await db.getAll(
      `SELECT report_month, gross_revenue, royalty_amount, status
       FROM royalty_reports WHERE unit_id = $1
       ORDER BY report_month DESC LIMIT 6`, [req.params.id]
    );

    const systemPrompt = `You are M-EasyFranchise AI, a franchise performance analyst. Provide actionable, specific insights. Always respond with JSON only.`;

    const userMessage = `Analyze this franchise unit's performance:
Brand: ${unit.brand_name}
Unit: ${unit.name} (${unit.unit_code})
Location: ${unit.city}, ${unit.state}
Status: ${unit.status}
Monthly Revenue: ${unit.currency} ${unit.monthly_revenue}
Health Score: ${unit.ai_health_score}/100
Franchisee: ${unit.franchisee_name || 'Unassigned'}
Contract End: ${unit.contract_end || 'N/A'}
Last 6 Months Revenue: ${JSON.stringify(royalties.map(r => ({ month: r.report_month, revenue: r.gross_revenue, status: r.status })))}

Return JSON: { "performance_rating": "excellent|good|average|poor", "risk_level": "low|medium|high", "insights": ["..."], "recommendations": ["..."], "renewal_outlook": "likely|uncertain|at_risk" }`;

    const result = await callGroq(systemPrompt, userMessage, 800);
    const parsed = JSON.parse(result.replace(/```json|```/g, '').trim());

    await db.run(
      `UPDATE franchise_units SET
         ai_risk_level = $1, updated_at = NOW()
       WHERE id = $2`,
      [parsed.risk_level, req.params.id]
    );

    await logAI(req.user.id, 'unit_analysis', 'unit', req.params.id);
    res.json(parsed);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// AI: General franchise chat assistant
app.post('/api/ai/chat', requireAuth, apiLimiter, async (req, res) => {
  try {
    const { message, brandId } = req.body;
    if (!message?.trim()) return res.status(400).json({ error: 'Message required' });

    let brandContext = '';
    if (brandId) {
      const brand = await db.getOne(
        'SELECT * FROM franchise_brands WHERE id = $1', [brandId]
      );
      if (brand) brandContext = `Active brand: ${brand.name} (${brand.industry}, ${brand.country})`;
    }

    const systemPrompt = `You are M-EasyFranchise AI, an intelligent franchise management assistant built into the MODUS AI ecosystem. 
Help franchise operators with: franchise expansion strategy, franchisee management, compliance, royalty management, training, support, and operations.
${brandContext}
Be specific, professional, and actionable. Keep responses concise (2-4 paragraphs max).`;

    const reply = await callGroq(systemPrompt, message, 800);
    await logAI(req.user.id, 'chat', 'general', null);
    res.json({ reply });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════
//  SYSTEM / HEALTH
// ════════════════════════════════════════════════════════════════════════

app.get('/api/health', async (req, res) => {
  try {
    const { rows } = await require('./db').pool.query('SELECT COUNT(*) AS c FROM users');
    res.json({
      status: 'ok',
      app:    'M-EasyFranchise AI',
      version: '1.0.0',
      db:     'PostgreSQL',
      ai:     !!GROQ_KEY,
      users:  parseInt(rows[0].c),
      ts:     new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

// Serve frontend
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ──────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║  M-EasyFranchise AI — Server v1.0                   ║
╠══════════════════════════════════════════════════════╣
║  Port:   ${PORT}                                        ║
║  DB:     PostgreSQL                                 ║
║  AI:     ${GROQ_KEY ? '✓ Groq AI Ready              ' : '✗ Add GROQ_API_KEY           '}║
║  Mode:   ${IS_PROD ? 'Production                   ' : 'Development                  '}║
╚══════════════════════════════════════════════════════╝
  `);
});
