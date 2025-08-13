// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
const { Resend } = require('resend');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================
   CORS
   ========================= */
const corsOptions = {
  origin: [
    'http://localhost:3000',
    'http://localhost:3001',
    'https://luma-backend-nfdc.onrender.com',
    'capacitor://localhost',
    'ionic://localhost',
    'http://localhost',
    'http://localhost:8080',
    'http://localhost:8100',
    /^https?:\/\/.*$/
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'Cache-Control',
    'User-Agent'
  ],
  exposedHeaders: ['Authorization'],
  preflightContinue: false,
  optionsSuccessStatus: 204
};
app.use(cors(corsOptions));

/* =========================
   JSON parsing + logging
   ========================= */
app.use(express.json({
  limit: '10mb',
  verify: (req, res, buf) => {
    if (!buf || buf.length === 0) return;
    const ct = (req.headers['content-type'] || '').toLowerCase();
    if (!ct.includes('application/json')) return;
    try { JSON.parse(buf); } catch (err) {
      console.error('❌ JSON Parse Error:', err.message);
      console.error('❌ Raw body:', buf.toString());
      throw new Error('Invalid JSON in request body');
    }
  }
}));
app.use((req, _res, next) => {
  if (req.method === 'POST' && req.body) {
    try {
      console.log('📥 Request Body Type:', typeof req.body);
      console.log('📥 Request Body:', JSON.stringify(req.body, null, 2));
    } catch { /* ignore */ }
  }
  next();
});
app.options('*', cors(corsOptions));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods','GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.header('Access-Control-Allow-Headers','Origin, X-Requested-With, Content-Type, Accept, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).send('');
  next();
});
app.use((req,_res,next)=>{ console.log(${new Date().toISOString()} - ${req.method} ${req.path}); next(); });

/* =========================
   JWT & Email
   ========================= */
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this';
const resend = new Resend(process.env.RESEND_API_KEY);

/* =========================
   PostgreSQL
   ========================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});
pool.connect((err, client, release) => {
  if (err) console.error('❌ Error connecting to PostgreSQL:', err.stack);
  else { console.log('✅ Connected to PostgreSQL database'); release(); }
});

/* =========================
   Gamification basics
   ========================= */
const XP_VALUES = {
  mood_entry: 10,
  journal_entry: 15,
  chat_message: 2,
  questionnaire_complete: 20,
  profile_update: 5
};
const levelFromXP = (xp) => Math.floor(xp / 100) + 1;
const todayUTCDateString = () => new Date().toISOString().split('T')[0];

/* =========================
   DB initialization
   ========================= */
async function initializeDatabase() {
  try {
    console.log('🗄️ Initializing database tables...');
    await pool.query(CREATE EXTENSION IF NOT EXISTS pgcrypto;);

    await pool.query(
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    );

    await pool.query(
      CREATE TABLE IF NOT EXISTS user_profiles (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        first_name VARCHAR(255),
        pronouns VARCHAR(50),
        join_date TIMESTAMPTZ DEFAULT NOW(),
        profile_color_hex VARCHAR(7) DEFAULT '#800080',
        notifications BOOLEAN DEFAULT true,
        biometric_auth BOOLEAN DEFAULT false,
        dark_mode BOOLEAN DEFAULT false,
        reminder_time TIME DEFAULT '19:00:00',
        data_purposes TEXT[] DEFAULT ARRAY['personalization','app_functionality'],
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    );

    await pool.query(
      CREATE TABLE IF NOT EXISTS password_resets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        reset_token VARCHAR(255) NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id)
      )
    );

    await pool.query(
      CREATE TABLE IF NOT EXISTS questionnaire_responses (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        completed BOOLEAN DEFAULT false,
        first_name VARCHAR(255),
        pronouns VARCHAR(50),
        main_goals TEXT[] DEFAULT ARRAY[]::TEXT[],
        communication_style VARCHAR(255),
        data_purpose VARCHAR(100) DEFAULT 'app_personalization',
        completed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    );
    await pool.query(
      ALTER TABLE questionnaire_responses
      ADD COLUMN IF NOT EXISTS consent_given BOOLEAN DEFAULT false
    );

    await pool.query(
      CREATE TABLE IF NOT EXISTS mood_entries (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        mood INTEGER NOT NULL CHECK (mood BETWEEN 1 AND 10),
        note TEXT,
        entry_date TIMESTAMPTZ NOT NULL,
        data_purpose VARCHAR(100) DEFAULT 'mood_tracking',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    );

    await pool.query(
      CREATE TABLE IF NOT EXISTS journal_entries (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        prompt TEXT,
        entry_date TIMESTAMPTZ NOT NULL,
        data_purpose VARCHAR(100) DEFAULT 'journaling',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    );

    await pool.query(
      CREATE TABLE IF NOT EXISTS chat_sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        start_time TIMESTAMPTZ DEFAULT NOW(),
        last_activity TIMESTAMPTZ DEFAULT NOW(),
        user_context JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    );

    await pool.query(
      CREATE TABLE IF NOT EXISTS chat_messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        session_id UUID REFERENCES chat_sessions(id) ON DELETE CASCADE,
        role VARCHAR(20) NOT NULL CHECK (role IN ('user','assistant','system')),
        content TEXT NOT NULL,
        contains_sensitive_data BOOLEAN DEFAULT false,
        timestamp TIMESTAMPTZ DEFAULT NOW(),
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    );

    await pool.query(
      CREATE TABLE IF NOT EXISTS gamification_progress (
        user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        xp INTEGER NOT NULL DEFAULT 0,
        level INTEGER NOT NULL DEFAULT 1,
        current_streak INTEGER NOT NULL DEFAULT 0,
        longest_streak INTEGER NOT NULL DEFAULT 0,
        last_activity_date DATE,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    );

    await pool.query(
      CREATE TABLE IF NOT EXISTS user_badges (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        badge_key VARCHAR(50) NOT NULL,
        earned_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, badge_key)
      )
    );
    await pool.query(CREATE INDEX IF NOT EXISTS idx_user_badges_user_id ON user_badges(user_id););

    console.log('✅ Database tables initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    throw error;
  }
}

/* =========================
   Auth middleware
   ========================= */
const authenticateToken = (req, res, next) => {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

/* =========================
   Email helper (Resend)
   ========================= */
async function sendPasswordResetEmail(email, resetToken, username) {
  try {
    const resetLink = luma://reset-password?token=${resetToken};
    const { data, error } = await resend.emails.send({
      from: 'Luma <onboard@resend.dev>',
      to: [email],
      subject: 'Reset Your Luma Password',
      html: 
        <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
          <h1 style="text-align:center">Reset Your Password</h1>
          <p>Hi ${username},</p>
          <p>Tap the button below to reset your password:</p>
          <p style="text-align:center">
            <a href="${resetLink}" style="background:#6b46c1;color:#fff;padding:12px 20px;border-radius:10px;text-decoration:none;">Reset Password</a>
          </p>
          <p>Or use this code in the app: <code>${resetToken}</code></p>
          <p style="color:#666">This link expires in 1 hour.</p>
        </div>
      
    });
    if (error) { console.error('❌ Resend email error:', error); return false; }
    console.log(✅ Password reset email sent (ID: ${data.id}));
    return true;
  } catch (err) {
    console.error('❌ Failed to send password reset email:', err);
    return false;
  }
}

/* =========================
   Gamification helpers
   ========================= */
async function ensureProgress(client, userId) {
  const res = await client.query(SELECT * FROM gamification_progress WHERE user_id = $1, [userId]);
  if (res.rows.length) return res.rows[0];
  const inserted = await client.query(
    INSERT INTO gamification_progress (user_id, xp, level, current_streak, longest_streak, last_activity_date, updated_at)
     VALUES ($1, 0, 1, 0, 0, NULL, NOW())
     RETURNING *,
    [userId]
  );
  return inserted.rows[0];
}
const getBadges = async (client, userId) => {
  const r = await client.query(SELECT badge_key FROM user_badges WHERE user_id=$1 ORDER BY earned_at ASC, [userId]);
  return r.rows.map(x => x.badge_key);
};
const awardBadgeIfNeeded = (client, userId, badgeKey) =>
  client.query(
    INSERT INTO user_badges (user_id, badge_key)
     VALUES ($1,$2) ON CONFLICT (user_id, badge_key) DO NOTHING,
    [userId, badgeKey]
  );
function diffDaysUTC(fromDateString, toDateString) {
  if (!fromDateString) return null;
  const from = new Date(fromDateString + 'T00:00:00.000Z');
  const to = new Date(toDateString + 'T00:00:00.000Z');
  return Math.floor((to - from) / (1000 * 60 * 60 * 24));
}
async function trackAction(userId, actionType) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    let progress = await ensureProgress(client, userId);

    const xpGain = XP_VALUES[actionType] || 0;
    let newXP = progress.xp + xpGain;

    const today = todayUTCDateString();
    const diff = diffDaysUTC(progress.last_activity_date, today);
    let newCurrentStreak;
    if (progress.last_activity_date == null) newCurrentStreak = 1;
    else if (diff === 0) newCurrentStreak = progress.current_streak || 1;
    else if (diff === 1) newCurrentStreak = (progress.current_streak || 0) + 1;
    else newCurrentStreak = 1;

    const newLongest = Math.max(progress.longest_streak || 0, newCurrentStreak);
    const newLevel = levelFromXP(newXP);

    const updated = await client.query(
      UPDATE gamification_progress
       SET xp=$1, level=$2, current_streak=$3, longest_streak=$4, last_activity_date=$5, updated_at=NOW()
       WHERE user_id=$6 RETURNING *,
      [newXP, newLevel, newCurrentStreak, newLongest, today, userId]
    );
    progress = updated.rows[0];

    const newly = [];
    if (actionType === 'mood_entry')  { await awardBadgeIfNeeded(client, userId, 'first_mood'); newly.push('first_mood'); }
    if (actionType === 'journal_entry'){ await awardBadgeIfNeeded(client, userId, 'first_journal'); newly.push('first_journal'); }
    if (actionType === 'chat_message') { await awardBadgeIfNeeded(client, userId, 'first_chat'); newly.push('first_chat'); }
    if (actionType === 'questionnaire_complete') { await awardBadgeIfNeeded(client, userId, 'onboard_complete'); newly.push('onboard_complete'); }

    for (const s of [3, 7, 30]) {
      if (progress.current_streak === s) { await awardBadgeIfNeeded(client, userId, streak_${s}); newly.push(streak_${s}); }
    }
    for (const x of [100, 500, 1000]) {
      const justReached = progress.xp - xpGain < x && progress.xp >= x;
      if (justReached) { await awardBadgeIfNeeded(client, userId, xp_${x}); newly.push(xp_${x}); }
    }

    await client.query('COMMIT');
    return { progress, newlyAwardedBadges: newly };
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('trackAction error:', e);
    return { progress: null, newlyAwardedBadges: [] };
  } finally {
    client.release();
  }
}

/* =========================
   AUTH ROUTES
   ========================= */
app.post('/api/auth/register', async (req, res) => {
  console.log('🚀 Registration request started');
  const client = await pool.connect();
  try {
    const { username, email, password } = req.body || {};
    if (!username || !email || !password)
      return res.status(400).json({ success: false, error: 'Username, email, and password are required' });
    if (password.length < 6)
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email))
      return res.status(400).json({ success: false, error: 'Please enter a valid email address' });

    const existingUser = await client.query(
      'SELECT id, username, email FROM users WHERE LOWER(username)=LOWER($1) OR LOWER(email)=LOWER($2)',
      [username, email]
    );
    if (existingUser.rows.length > 0) {
      const existing = existingUser.rows[0];
      const msg = existing.username.toLowerCase() === username.toLowerCase() ? 'Username already exists' : 'Email already exists';
      return res.status(400).json({ success: false, error: msg });
    }

    const hashed = await bcrypt.hash(password, 10);

    await client.query('BEGIN');
    const userResult = await client.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1,$2,$3) RETURNING id, username, email, created_at',
      [username, email, hashed]
    );
    const newUser = userResult.rows[0];

    await client.query(
      INSERT INTO user_profiles (user_id, first_name, pronouns, join_date, profile_color_hex, notifications, biometric_auth, dark_mode, reminder_time, data_purposes)
       VALUES ($1, '', '', NOW(), '#800080', true, false, false, '19:00:00', ARRAY['personalization','app_functionality']),
      [newUser.id]
    );
    await client.query(
      INSERT INTO questionnaire_responses (user_id, completed, first_name, pronouns, main_goals, communication_style, data_purpose, consent_given)
       VALUES ($1,false,'','',ARRAY[]::TEXT[],'','app_personalization',false),
      [newUser.id]
    );
    await client.query(
      INSERT INTO gamification_progress (user_id, xp, level, current_streak, longest_streak, last_activity_date, updated_at)
       VALUES ($1,0,1,0,0,NULL,NOW()) ON CONFLICT (user_id) DO NOTHING,
      [newUser.id]
    );
    await client.query('COMMIT');

    const token = jwt.sign({ userId: newUser.id, username: newUser.username }, JWT_SECRET, { expiresIn: '7d' });
    res.status(200).json({ success: true, message: 'User registered successfully', token, user: { id: newUser.id, username: newUser.username, email: newUser.email } });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('💥 REGISTRATION ERROR:', e);
    let errorMessage = 'Server error during registration';
    let statusCode = 500;
    if (e.code === '23505') {
      if (e.detail?.includes('username')) errorMessage = 'Username already exists';
      else if (e.detail?.includes('email')) errorMessage = 'Email already exists';
      else errorMessage = 'User already exists';
      statusCode = 400;
    }
    res.status(statusCode).json({ success: false, error: errorMessage });
  } finally { client.release(); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password)
      return res.status(400).json({ success: false, error: 'Username and password are required' });

    const r = await pool.query(
      SELECT id, username, email, password_hash
       FROM users
       WHERE LOWER(username)=LOWER($1) OR LOWER(email)=LOWER($1),
      [username]
    );
    if (!r.rows.length)
      return res.status(401).json({ success: false, error: 'Invalid credentials' });

    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ success: false, error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, message: 'Login successful', token, user: { id: user.id, username: user.username, email: user.email } });
  } catch (e) {
    console.error('💥 LOGIN ERROR:', e);
    res.status(500).json({ success: false, error: 'Server error during login' });
  }
});

/* =========================
   PASSWORD RESET
   ========================= */
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ success: false, error: 'Email is required' });

    const r = await pool.query('SELECT id, username, email FROM users WHERE LOWER(email)=LOWER($1)', [email]);
    if (!r.rows.length) return res.json({ success: true, message: 'If an account exists, email sent.' });

    const user = r.rows[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000);
    await pool.query(
      INSERT INTO password_resets (user_id, reset_token, expires_at, created_at)
       VALUES ($1,$2,$3,NOW())
       ON CONFLICT (user_id) DO UPDATE SET reset_token=$2, expires_at=$3, created_at=NOW(), used=false,
      [user.id, token, expires]
    );
    if (process.env.RESEND_API_KEY) await sendPasswordResetEmail(email, token, user.username || 'User');
    res.json({ success: true, message: 'If an account exists, email sent.' });
  } catch (e) {
    console.error('Forgot password error:', e);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) return res.status(400).json({ success: false, error: 'Token and new password required' });
    if (newPassword.length < 6) return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });

    const r = await pool.query(
      SELECT pr.*, u.id as user_id
       FROM password_resets pr
       JOIN users u ON u.id = pr.user_id
       WHERE pr.reset_token=$1 AND pr.expires_at > NOW() AND pr.used=false,
      [token]
    );
    if (!r.rows.length) return res.status(400).json({ success: false, error: 'Invalid or expired reset token' });

    const row = r.rows[0];
    const hashed = await bcrypt.hash(newPassword, 10);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2', [hashed, row.user_id]);
      await client.query('UPDATE password_resets SET used=true WHERE id=$1', [row.id]);
      await client.query('COMMIT');
      res.json({ success: true, message: 'Password reset successful' });
    } catch (e) {
      await client.query('ROLLBACK'); throw e;
    } finally { client.release(); }
  } catch (e) {
    console.error('Reset password error:', e);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

/* =========================
   ME / LOGOUT
   ========================= */
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query('SELECT id, username, email, created_at FROM users WHERE id=$1', [req.user.userId]);
    if (!r.rows.length) return res.status(404).json({ success: false, error: 'User not found' });
    res.json({ success: true, ...r.rows[0] });
  } catch (e) {
    console.error('Get user error:', e);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});
app.post('/api/auth/logout', authenticateToken, (_req,res)=> res.json({ success:true, message:'Logged out successfully' }));

/* =========================
   QUESTIONNAIRE
   ========================= */
app.get('/api/questionnaire', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM questionnaire_responses WHERE user_id=$1', [req.user.userId]);
    if (!r.rows.length) {
      return res.json({ success: true, completed: false, responses: { firstName: "", pronouns: "", mainGoals: [], communicationStyle: "" } });
    }
    const q = r.rows[0];
    res.json({
      success: true,
      completed: q.completed,
      responses: {
        firstName: q.first_name || "",
        pronouns: q.pronouns || "",
        mainGoals: q.main_goals || [],
        communicationStyle: q.communication_style || ""
      },
      completedAt: q.completed_at
    });
  } catch (e) {
    console.error('Questionnaire load error:', e);
    res.status(500).json({ success: false, error: 'Failed to load questionnaire' });
  }
});
app.post('/api/questionnaire', authenticateToken, async (req, res) => {
  try {
    const { responses } = req.body || {};
    if (!responses || typeof responses !== 'object')
      return res.status(400).json({ success: false, error: 'Invalid questionnaire responses' });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        UPDATE questionnaire_responses 
         SET completed=true, first_name=$1, pronouns=$2, main_goals=$3, communication_style=$4, 
             data_purpose='app_personalization', consent_given=true, completed_at=NOW(), updated_at=NOW()
         WHERE user_id=$5,
        [
          responses.firstName || '',
          responses.pronouns || '',
          responses.mainGoals || [],
          responses.communicationStyle || '',
          req.user.userId
        ]
      );
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); throw e; }
    finally { client.release(); }

    await trackAction(req.user.userId, 'questionnaire_complete');
    res.json({ success: true, message: 'Questionnaire completed successfully' });
  } catch (e) {
    console.error('Questionnaire save error:', e);
    res.status(500).json({ success: false, error: 'Failed to save questionnaire' });
  }
});

/* =========================
   PROFILE
   ========================= */
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM user_profiles WHERE user_id=$1', [req.user.userId]);
    if (!r.rows.length) return res.status(404).json({ success: false, error: 'Profile not found' });
    const p = r.rows[0];
    res.json({
      success: true,
      firstName: p.first_name || "",
      pronouns: p.pronouns || "",
      joinDate: p.join_date,
      profileColorHex: p.profile_color_hex || "#800080",
      notifications: p.notifications,
      biometricAuth: p.biometric_auth,
      darkMode: p.dark_mode,
      reminderTime: p.reminder_time,
      dataPurposes: p.data_purposes || []
    });
  } catch (e) {
    console.error('Profile load error:', e);
    res.status(500).json({ success: false, error: 'Failed to load profile' });
  }
});
app.post('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { firstName, pronouns, joinDate, profileColorHex, notifications, biometricAuth, darkMode, reminderTime, dataPurposes } = req.body || {};
    let purposes = ['personalization', 'app_functionality'];
    if (Array.isArray(dataPurposes)) purposes = dataPurposes;
    else if (typeof dataPurposes === 'string') purposes = [dataPurposes];

    const r = await pool.query(
      UPDATE user_profiles 
       SET first_name=$1, pronouns=$2, 
           join_date=COALESCE($3, join_date),
           profile_color_hex=COALESCE($4, profile_color_hex),
           notifications=COALESCE($5, notifications),
           biometric_auth=COALESCE($6, biometric_auth),
           dark_mode=COALESCE($7, dark_mode),
           reminder_time=COALESCE($8, reminder_time),
           data_purposes=$9,
           updated_at=NOW()
       WHERE user_id=$10
       RETURNING first_name, pronouns, data_purposes,
      [
        firstName || '',
        pronouns || '',
        joinDate || null,
        profileColorHex || '#800080',
        notifications !== undefined ? notifications : true,
        biometricAuth !== undefined ? biometricAuth : false,
        darkMode !== undefined ? darkMode : false,
        reminderTime || '19:00:00',
        purposes,
        req.user.userId
      ]
    );

    await trackAction(req.user.userId, 'profile_update');
    res.json({ success: true, message: 'Profile updated successfully', profile: r.rows[0] });
  } catch (e) {
    console.error('💥 Profile save error:', e);
    res.status(500).json({ success: false, error: 'Failed to save profile' });
  }
});

/* =========================
   MOOD
   ========================= */
app.get('/api/mood', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query(
      SELECT id, mood, note, entry_date as date, data_purpose
       FROM mood_entries WHERE user_id=$1 ORDER BY entry_date DESC,
      [req.user.userId]
    );
    res.json({ success: true, data: r.rows });
  } catch (e) {
    console.error('Mood load error:', e);
    res.status(500).json({ success: false, error: 'Failed to load mood entries' });
  }
});
app.post('/api/mood', authenticateToken, async (req, res) => {
  try {
    const { mood, note, date, dataPurpose = 'mood_tracking' } = req.body || {};
    if (!mood || !date) return res.status(400).json({ success: false, error: 'Mood and date are required' });
    if (mood < 1 || mood > 10) return res.status(400).json({ success: false, error: 'Mood must be between 1 and 10' });

    const r = await pool.query(
      INSERT INTO mood_entries (user_id, mood, note, entry_date, data_purpose)
       VALUES ($1,$2,$3,$4,$5) RETURNING *,
      [req.user.userId, parseInt(mood, 10), note || null, date, dataPurpose]
    );

    const gamify = await trackAction(req.user.userId, 'mood_entry');
    res.json({ success: true, message: 'Mood entry saved successfully', entry: r.rows[0], gamification: gamify });
  } catch (e) {
    console.error('Mood save error:', e);
    res.status(500).json({ success: false, error: 'Failed to save mood entry' });
  }
});

/* =========================
   JOURNAL
   ========================= */
app.get('/api/journal', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query(
      SELECT id, content, prompt, entry_date as date, data_purpose
       FROM journal_entries WHERE user_id=$1 ORDER BY entry_date DESC,
      [req.user.userId]
    );
    res.json({ success: true, data: r.rows });
  } catch (e) {
    console.error('Journal load error:', e);
    res.status(500).json({ success: false, error: 'Failed to load journal entries' });
  }
});
app.post('/api/journal', authenticateToken, async (req, res) => {
  try {
    const { content, prompt, date, dataPurpose = 'journaling' } = req.body || {};
    if (!content || !date) return res.status(400).json({ success: false, error: 'Content and date are required' });
    if (content.trim().length === 0) return res.status(400).json({ success: false, error: 'Content cannot be empty' });

    const r = await pool.query(
      INSERT INTO journal_entries (user_id, content, prompt, entry_date, data_purpose)
       VALUES ($1,$2,$3,$4,$5) RETURNING *,
      [req.user.userId, content.trim(), prompt || null, date, dataPurpose]
    );

    const gamify = await trackAction(req.user.userId, 'journal_entry');
    res.json({ success: true, message: 'Journal entry saved successfully', entry: r.rows[0], gamification: gamify });
  } catch (e) {
    console.error('Journal save error:', e);
    res.status(500).json({ success: false, error: 'Failed to save journal entry' });
  }
});

/* =========================
   CHAT — OpenAI integration
   ========================= */

// Therapist system prompt (kept concise but strong)
const THERAPIST_SYSTEM_PROMPT = 
You are Luma, a warm, evidence-based AI therapist. Goals:
- Build rapport with empathy and validation.
- Ask short, open-ended questions (1 per turn).
- Use CBT/DBT/Motivational Interviewing tools when helpful.
- Be concise (2–4 short sentences).
- Avoid medical or legal claims; suggest professional help if risk appears.
- If the user expresses suicidal intent or self-harm risk: (1) validate feelings, (2) encourage contacting local emergency services or a crisis line, (3) suggest reaching out to a trusted person, (4) ask if they feel safe right now.
- Never reveal or invent PII. Do not mention policies.
;

const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';
const OPENAI_URL = 'https://api.openai.com/v1/chat/completions';

// Pull last N messages from this chat session to keep context tight
async function getRecentChatForSession(sessionId, limit = 12) {
  const r = await pool.query(
    SELECT role, content
     FROM chat_messages
     WHERE session_id=$1
     ORDER BY timestamp DESC
     LIMIT $2,
    [sessionId, limit]
  );
  // reverse chronological -> chronological
  return r.rows.reverse();
}

function toOpenAIMessages(historyRows, userDisplayName = 'User') {
  const mapped = historyRows.map((m) => {
    const role = m.role === 'assistant' ? 'assistant'
              : m.role === 'system' ? 'system'
              : 'user';
    return { role, content: m.content };
  });
  // Prepend system instruction
  return [
    { role: 'system', content: THERAPIST_SYSTEM_PROMPT.trim() },
    ...mapped
  ];
}

async function generateTherapeuticReply({ sessionId, userMessage }) {
  if (!process.env.OPENAI_API_KEY) {
    return "I'm here with you. Tell me more about what's on your mind.";
  }

  const history = await getRecentChatForSession(sessionId, 14);
  const messages = toOpenAIMessages(history);
  // Add the latest user message at the end
  messages.push({ role: 'user', content: userMessage });

  const body = {
    model: OPENAI_MODEL,
    messages,
    temperature: 0.7,
    max_tokens: 220,
    presence_penalty: 0.4,
    frequency_penalty: 0.2
  };

  const resp = await fetch(OPENAI_URL, {
    method: 'POST',
    headers: {
      'Authorization': Bearer ${process.env.OPENAI_API_KEY},
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    const text = await resp.text().catch(()=>'');
    console.error('OpenAI error:', resp.status, text);
    return "I'm here with you. Tell me more about what's on your mind.";
  }

  const data = await resp.json();
  const reply = data?.choices?.[0]?.message?.content?.trim();
  return reply || "I'm here with you. Tell me more about what's on your mind.";
}

app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    const { message, sessionId, consentedToAI } = req.body || {};
    if (!consentedToAI) {
      return res.status(403).json({ success: false, error: 'AI processing consent required', requiresConsent: true });
    }

    // Ensure session exists or create one
    let session = null;
    if (sessionId) {
      const s = await pool.query('SELECT * FROM chat_sessions WHERE id=$1 AND user_id=$2', [sessionId, req.user.userId]);
      if (s.rows.length) session = s.rows[0];
    }
    if (!session) {
      const ins = await pool.query(
        INSERT INTO chat_sessions (user_id, start_time, last_activity, user_context)
         VALUES ($1,NOW(),NOW(),$2) RETURNING *,
        [req.user.userId, JSON.stringify({})]
      );
      session = ins.rows[0];
    }

    const sensitiveKeywords = ['suicide', 'self-harm', 'kill myself', 'kill myself.', 'medication', 'doctor', 'therapist'];
    const containsSensitive = !!message && sensitiveKeywords.some(k => message.toLowerCase().includes(k));

    // Store user message
    await pool.query(
      INSERT INTO chat_messages (session_id, role, content, contains_sensitive_data, timestamp)
       VALUES ($1,'user',$2,$3,NOW()),
      [session.id, message || '', containsSensitive]
    );

    // Gamify: chat message
    const gamify = await trackAction(req.user.userId, 'chat_message');

    // Generate AI response (or fallback)
    const reply = await generateTherapeuticReply({ sessionId: session.id, userMessage: message || '' });

    // Store assistant message
    await pool.query(
      INSERT INTO chat_messages (session_id, role, content, timestamp)
       VALUES ($1,'assistant',$2,NOW()),
      [session.id, reply]
    );

    res.json({ success: true, response: reply, sessionId: session.id, gamification: gamify });
  } catch (e) {
    console.error('Chat error:', e);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

/* =========================
   GAMIFY PROGRESS
   ========================= */
app.get('/api/gamify/progress', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const progress = await ensureProgress(client, req.user.userId);
      const badges = await getBadges(client, req.user.userId);
      await client.query('COMMIT');

      const nextLevel = levelFromXP(progress.xp) + 1;
      const nextLevelXP = (nextLevel - 1) * 100;
      res.json({
        success: true,
        progress: {
          xp: progress.xp,
          level: progress.level,
          currentStreak: progress.current_streak,
          longestStreak: progress.longest_streak,
          lastActivityDate: progress.last_activity_date
        },
        badges,
        nextLevelXP
      });
    } catch (e) { await client.query('ROLLBACK'); throw e; }
    finally { client.release(); }
  } catch (e) {
    console.error('gamify/progress error:', e);
    res.status(500).json({ success: false, error: 'Failed to load progress' });
  }
});

/* =========================
   PRIVACY ROUTES - FIXED
   ========================= */
// FIXED: Delete all data but keep the account and questionnaire completion status
app.delete('/api/privacy/delete-all', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const client = await pool.connect();
  try {
    console.log(🗑️ Starting data deletion for user: ${userId});
    await client.query('BEGIN');

    // Delete chat data
    const chatMsgDelete = await client.query(
      DELETE FROM chat_messages WHERE session_id IN (SELECT id FROM chat_sessions WHERE user_id=$1),
      [userId]
    );
    const chatSessionDelete = await client.query(
      DELETE FROM chat_sessions WHERE user_id=$1,
      [userId]
    );
    
    // Delete mood and journal entries
    const moodDelete = await client.query(
      DELETE FROM mood_entries WHERE user_id=$1,
      [userId]
    );
    const journalDelete = await client.query(
      DELETE FROM journal_entries WHERE user_id=$1,
      [userId]
    );
    
    // Delete badges and gamification progress
    const badgesDelete = await client.query(
      DELETE FROM user_badges WHERE user_id=$1,
      [userId]
    );
    const gamifyDelete = await client.query(
      DELETE FROM gamification_progress WHERE user_id=$1,
      [userId]
    );

    // FIXED: Don't reset questionnaire completion status
    // Only clear the personal data, but keep completed=true so user doesn't go back to onboarding
    const questionnaireReset = await client.query(
      UPDATE questionnaire_responses
         SET first_name='',
             pronouns='',
             main_goals=ARRAY[]::TEXT[],
             communication_style='',
             data_purpose='app_personalization',
             consent_given=false,
             updated_at=NOW()
       WHERE user_id=$1,
      [userId]
    );

    // FIXED: Also clear profile data but don't delete the profile record
    const profileReset = await client.query(
      UPDATE user_profiles
         SET first_name='',
             pronouns='',
             updated_at=NOW()
       WHERE user_id=$1,
      [userId]
    );

    await client.query('COMMIT');
    
    console.log(✅ Data deletion completed for user: ${userId});
    console.log(📊 Deletion summary:
      - Chat messages: ${chatMsgDelete.rowCount}
      - Chat sessions: ${chatSessionDelete.rowCount}
      - Mood entries: ${moodDelete.rowCount}
      - Journal entries: ${journalDelete.rowCount}
      - Badges: ${badgesDelete.rowCount}
      - Gamification rows: ${gamifyDelete.rowCount}
      - Questionnaire updated: ${questionnaireReset.rowCount}
      - Profile updated: ${profileReset.rowCount});

    res.json({
      success: true,
      message: 'All personal data deleted for this account (account retained).',
      deleted: {
        chatMessages: chatMsgDelete.rowCount,
        chatSessions: chatSessionDelete.rowCount,
        moods: moodDelete.rowCount,
        journals: journalDelete.rowCount,
        badges: badgesDelete.rowCount,
        gamificationRows: gamifyDelete.rowCount,
        questionnaireRowsUpdated: questionnaireReset.rowCount,
        profileRowsUpdated: profileReset.rowCount
      }
    });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('❌ delete-all error:', e);
    res.status(500).json({ success: false, error: 'Failed to delete data' });
  } finally { client.release(); }
});

// Fully delete the account (cascades via FK)
app.delete('/api/privacy/delete-account', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const client = await pool.connect();
  try {
    console.log(🗑️ Starting full account deletion for user: ${userId});
    await client.query('BEGIN');
    await client.query('DELETE FROM users WHERE id=$1', [userId]);
    await client.query('COMMIT');
    console.log(✅ Account fully deleted for user: ${userId});
    res.json({ success: true, message: 'Account and all data permanently deleted.' });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('❌ delete-account error:', e);
    res.status(500).json({ success: false, error: 'Failed to delete account' });
  } finally { client.release(); }
});

/* =========================
   DEBUG & HEALTH
   ========================= */
app.get('/api/debug/db-test', async (_req, res) => {
  try {
    const client = await pool.connect();
    const users = await client.query('SELECT COUNT(*) AS c FROM users');
    const profiles = await client.query('SELECT COUNT(*) AS c FROM user_profiles');
    const qn = await client.query('SELECT COUNT(*) AS c FROM questionnaire_responses');
    client.release();
    res.json({
      success: true,
      message: 'DB ok',
      data: {
        users: parseInt(users.rows[0].c, 10),
        profiles: parseInt(profiles.rows[0].c, 10),
        questionnaires: parseInt(qn.rows[0].c, 10)
      }
    });
  } catch (e) {
    console.error('db-test error:', e);
    res.status(500).json({ success: false, error: 'Database test failed' });
  }
});
app.get('/api/debug/users', async (_req, res) => {
  try {
    if (process.env.NODE_ENV === 'production') return res.status(404).json({ error: 'Not found' });
    const u = await pool.query('SELECT id, username, email, created_at FROM users ORDER BY created_at DESC LIMIT 10');
    res.json({ success: true, count: u.rows.length, users: u.rows });
  } catch (e) {
    console.error('debug/users error:', e);
    res.status(500).json({ success: false, error: 'Failed to fetch users' });
  }
});
app.get('/health', (_req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '6.7.0 - Fixed Privacy Delete',
    database: 'PostgreSQL',
    openai: process.env.OPENAI_API_KEY ? 'Available' : 'Fallback mode',
    features: {
      passwordReset: 'Available',
      profileFixes: 'Applied',
      gamification: 'XP/Streaks/Badges',
      deleteAllData: 'Fixed - Preserves onboarding status',
      deleteAccount: 'Available',
      therapistAI: process.env.OPENAI_API_KEY ? 'On' : 'Off'
    },
    success: true
  });
});
app.get('/', (_req, res) => {
  res.json({
    message: 'Luma Backend API',
    version: '6.7.0 - Fixed Privacy Delete',
    status: 'running',
    endpoints: {
      health: '/health',
      auth: '/api/auth/*',
      profile: '/api/profile',
      mood: '/api/mood',
      journal: '/api/journal',
      chat: '/api/chat',
      gamify: '/api/gamify/progress',
      privacy: '/api/privacy/*'
    }
  });
});

/* =========================
   404 + error
   ========================= */
app.use('*', (_req, res) => res.status(404).json({ success: false, error: 'Route not found' }));
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

/* =========================
   START
   ========================= */
const startServer = async () => {
  try {
    console.log('🚀 Starting Luma Backend Server...');
    const c = await pool.connect(); c.release();
    await initializeDatabase();
    console.log('✅ Database initialization complete');
    app.listen(PORT, () => {
      console.log(✅ Luma backend running on port ${PORT});
      console.log(🌐 Server URL: https://luma-backend-nfdc.onrender.com);
      console.log(🤖 AI Mode: ${process.env.OPENAI_API_KEY ? 'OpenAI' : 'Fallback responses'});
      console.log('🧹 Privacy deletes: Fixed - preserves onboarding status');
    });
  } catch (e) {
    console.error('❌ Failed to start server:', e);
    process.exit(1);
  }
};
startServer();
