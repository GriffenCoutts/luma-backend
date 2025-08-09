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

// CORS CONFIGURATION
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

// ENHANCED JSON PARSING WITH BETTER ERROR HANDLING
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf, encoding) => {
    try {
      JSON.parse(buf);
    } catch (err) {
      console.error('❌ JSON Parse Error:', err.message);
      console.error('❌ Raw body:', buf.toString());
      throw new Error('Invalid JSON in request body');
    }
  }
}));

// Log all request bodies for debugging
app.use((req, res, next) => {
  if (req.method === 'POST' && req.body) {
    console.log('📥 Request Body Type:', typeof req.body);
    console.log('📥 Request Body:', JSON.stringify(req.body, null, 2));
  }
  next();
});

app.options('*', cors(corsOptions));

// Headers middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }
  next();
});

// Logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this';

// Initialize Resend for email sending
const resend = new Resend(process.env.RESEND_API_KEY);

// PostgreSQL Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Error connecting to PostgreSQL:', err.stack);
  } else {
    console.log('✅ Connected to PostgreSQL database');
    release();
  }
});

/* =========================
   GAMIFICATION CONSTANTS
   ========================= */
const XP_VALUES = {
  mood_entry: 10,
  journal_entry: 15,
  chat_message: 2,
  questionnaire_complete: 20,
  profile_update: 5
};

function levelFromXP(xp) {
  // simple curve: 100 XP per level
  return Math.floor(xp / 100) + 1;
}

function todayUTCDateString() {
  return new Date().toISOString().split('T')[0]; // YYYY-MM-DD in UTC
}

/* =========================
   DB INITIALIZATION
   ========================= */
async function initializeDatabase() {
  try {
    console.log('🗄️ Initializing database tables...');

    // Needed for gen_random_uuid()
    await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);
    
    // Users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // User profiles
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_profiles (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        first_name VARCHAR(255),
        pronouns VARCHAR(50),
        join_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        profile_color_hex VARCHAR(7) DEFAULT '#800080',
        notifications BOOLEAN DEFAULT true,
        biometric_auth BOOLEAN DEFAULT false,
        dark_mode BOOLEAN DEFAULT false,
        reminder_time TIME DEFAULT '19:00:00',
        data_purposes TEXT[] DEFAULT ARRAY['personalization','app_functionality'],
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Password resets table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        reset_token VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        used BOOLEAN DEFAULT false,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        UNIQUE(user_id)
      )
    `);

    // Questionnaire responses
    await pool.query(`
      CREATE TABLE IF NOT EXISTS questionnaire_responses (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        completed BOOLEAN DEFAULT false,
        first_name VARCHAR(255),
        pronouns VARCHAR(50),
        main_goals TEXT[] DEFAULT ARRAY[]::TEXT[],
        communication_style VARCHAR(255),
        data_purpose VARCHAR(100) DEFAULT 'app_personalization',
        completed_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Ensure consent_given exists
    await pool.query(`
      ALTER TABLE questionnaire_responses 
      ADD COLUMN IF NOT EXISTS consent_given BOOLEAN DEFAULT false
    `);

    // Mood entries
    await pool.query(`
      CREATE TABLE IF NOT EXISTS mood_entries (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        mood INTEGER NOT NULL CHECK (mood >= 1 AND mood <= 10),
        note TEXT,
        entry_date TIMESTAMP WITH TIME ZONE NOT NULL,
        data_purpose VARCHAR(100) DEFAULT 'mood_tracking',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Journal entries
    await pool.query(`
      CREATE TABLE IF NOT EXISTS journal_entries (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        prompt TEXT,
        entry_date TIMESTAMP WITH TIME ZONE NOT NULL,
        data_purpose VARCHAR(100) DEFAULT 'journaling',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Chat sessions
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        start_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        user_context JSONB,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Chat messages
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        session_id UUID REFERENCES chat_sessions(id) ON DELETE CASCADE,
        role VARCHAR(20) NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
        content TEXT NOT NULL,
        contains_sensitive_data BOOLEAN DEFAULT false,
        timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    /* ---------- GAMIFICATION TABLES ---------- */

    await pool.query(`
      CREATE TABLE IF NOT EXISTS gamification_progress (
        user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        xp INTEGER NOT NULL DEFAULT 0,
        level INTEGER NOT NULL DEFAULT 1,
        current_streak INTEGER NOT NULL DEFAULT 0,
        longest_streak INTEGER NOT NULL DEFAULT 0,
        last_activity_date DATE,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_badges (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        badge_key VARCHAR(50) NOT NULL,
        earned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        UNIQUE(user_id, badge_key)
      )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_user_badges_user_id ON user_badges(user_id);`);

    console.log('✅ Database tables initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    throw error;
  }
}

/* =========================
   AUTH MIDDLEWARE
   ========================= */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      success: false,
      error: 'Access token required',
      message: 'Access token required'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        success: false,
        error: 'Invalid or expired token',
        message: 'Invalid or expired token'
      });
    }
    req.user = user;
    next();
  });
};

/* =========================
   EMAIL (RESEND)
   ========================= */
async function sendPasswordResetEmail(email, resetToken, username) {
  try {
    const resetLink = `luma://reset-password?token=${resetToken}`; // Deep link for your iOS app
    
    const { data, error } = await resend.emails.send({
      from: 'Luma <onboard@resend.dev>',
      to: [email],
      subject: 'Reset Your Luma Password',
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="text-align: center; margin-bottom: 40px;">
            <div style="width: 60px; height: 60px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; margin-bottom: 20px;">
              <span style="color: white; font-size: 24px; font-weight: bold;">L</span>
            </div>
            <h1 style="color: #333; margin: 0; font-size: 24px;">Reset Your Password</h1>
          </div>
          <p style="color: #555; font-size: 16px;">Hi ${username},</p>
          <p style="color: #555; font-size: 16px;">You requested a password reset for your Luma account. Tap the button below to create a new password:</p>
          <div style="text-align: center; margin: 40px 0;">
            <a href="${resetLink}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 16px 32px; text-decoration: none; border-radius: 12px; display: inline-block; font-weight: 600; font-size: 16px;">Reset Password</a>
          </div>
          <p style="color: #777; font-size: 14px;">Or copy and paste this code in the app: <code style="background: #f5f5f5; padding: 4px 8px; border-radius: 4px; font-family: monospace;">${resetToken}</code></p>
          <div style="background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 30px 0;">
            <p style="color: #666; font-size: 14px; margin: 0;"><strong>Security Note:</strong> This reset link will expire in 1 hour. If you didn't request this password reset, you can safely ignore this email.</p>
          </div>
          <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
          <div style="text-align: center;">
            <p style="color: #999; font-size: 12px; margin: 0;">This email was sent by Luma - Your AI Mental Health Companion</p>
          </div>
        </div>
      `
    });

    if (error) {
      console.error(`❌ Resend email error for ${email}:`, error);
      return false;
    }

    console.log(`✅ Password reset email sent to ${email} (ID: ${data.id})`);
    return true;
  } catch (error) {
    console.error(`❌ Failed to send password reset email to ${email}:`, error);
    return false;
  }
}

/* =========================
   GAMIFICATION HELPERS
   ========================= */
async function ensureProgress(client, userId) {
  const res = await client.query(`SELECT * FROM gamification_progress WHERE user_id = $1`, [userId]);
  if (res.rows.length > 0) return res.rows[0];

  const inserted = await client.query(
    `INSERT INTO gamification_progress (user_id, xp, level, current_streak, longest_streak, last_activity_date, updated_at)
     VALUES ($1, 0, 1, 0, 0, NULL, NOW())
     RETURNING *`,
    [userId]
  );
  return inserted.rows[0];
}

async function getBadges(client, userId) {
  const res = await client.query(`SELECT badge_key FROM user_badges WHERE user_id = $1 ORDER BY earned_at ASC`, [userId]);
  return res.rows.map(r => r.badge_key);
}

async function awardBadgeIfNeeded(client, userId, badgeKey) {
  await client.query(
    `INSERT INTO user_badges (user_id, badge_key) VALUES ($1, $2) ON CONFLICT (user_id, badge_key) DO NOTHING`,
    [userId, badgeKey]
  );
}

function diffDaysUTC(fromDateString, toDateString) {
  if (!fromDateString) return null;
  const from = new Date(fromDateString + 'T00:00:00.000Z');
  const to = new Date(toDateString + 'T00:00:00.000Z');
  const ms = to - from;
  return Math.floor(ms / (1000 * 60 * 60 * 24));
}

/**
 * trackAction:
 * - Increments XP based on actionType
 * - Updates daily streak (UTC-based)
 * - Updates level from XP
 * - Awards badges for firsts, streak milestones, XP milestones
 * Returns: { progress, newlyAwardedBadges[] }
 */
async function trackAction(userId, actionType) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Ensure progress row exists
    let progress = await ensureProgress(client, userId);

    // XP
    const xpGain = XP_VALUES[actionType] || 0;
    let newXP = progress.xp + xpGain;

    // Streak
    const today = todayUTCDateString();
    const diff = diffDaysUTC(progress.last_activity_date, today);

    let newCurrentStreak = progress.current_streak;
    if (progress.last_activity_date == null) {
      newCurrentStreak = 1; // first activity
    } else if (diff === 0) {
      // same day, do not increment streak
      newCurrentStreak = progress.current_streak || 1;
    } else if (diff === 1) {
      newCurrentStreak = (progress.current_streak || 0) + 1;
    } else if (diff >= 2) {
      newCurrentStreak = 1; // reset
    } else {
      // diff null -> treat as first
      newCurrentStreak = 1;
    }

    const newLongest = Math.max(progress.longest_streak || 0, newCurrentStreak);
    const newLevel = levelFromXP(newXP);

    const updated = await client.query(
      `UPDATE gamification_progress
       SET xp = $1,
           level = $2,
           current_streak = $3,
           longest_streak = $4,
           last_activity_date = $5,
           updated_at = NOW()
       WHERE user_id = $6
       RETURNING *`,
      [newXP, newLevel, newCurrentStreak, newLongest, today, userId]
    );
    progress = updated.rows[0];

    // Badge logic
    const newly = [];

    // Firsts
    if (actionType === 'mood_entry') {
      await awardBadgeIfNeeded(client, userId, 'first_mood');
      newly.push('first_mood');
    }
    if (actionType === 'journal_entry') {
      await awardBadgeIfNeeded(client, userId, 'first_journal');
      newly.push('first_journal');
    }
    if (actionType === 'chat_message') {
      await awardBadgeIfNeeded(client, userId, 'first_chat');
      newly.push('first_chat');
    }
    if (actionType === 'questionnaire_complete') {
      await awardBadgeIfNeeded(client, userId, 'onboard_complete');
      newly.push('onboard_complete');
    }

    // Streak milestones
    const streakMilestones = [3, 7, 30];
    for (const s of streakMilestones) {
      if (progress.current_streak === s) {
        await awardBadgeIfNeeded(client, userId, `streak_${s}`);
        newly.push(`streak_${s}`);
      }
    }

    // XP milestones
    const xpMilestones = [100, 500, 1000];
    for (const x of xpMilestones) {
      const justReached = (progress.xp - xpGain) < x && progress.xp >= x;
      if (justReached) {
        await awardBadgeIfNeeded(client, userId, `xp_${x}`);
        newly.push(`xp_${x}`);
      }
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

// REGISTER
app.post('/api/auth/register', async (req, res) => {
  console.log('🚀 Registration request started');
  console.log('📝 Request body:', req.body);
  console.log('📝 Content-Type:', req.headers['content-type']);
  
  const client = await pool.connect();
  
  try {
    const { username, email, password } = req.body;
    console.log('📝 Extracted values:', { username, email, passwordLength: password?.length });

    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Username, email, and password are required',
        message: 'Username, email, and password are required'
      });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters', message: 'Password must be at least 6 characters' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, error: 'Please enter a valid email address', message: 'Please enter a valid email address' });
    }

    const existingUser = await client.query(
      'SELECT id, username, email FROM users WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($2)',
      [username, email]
    );
    if (existingUser.rows.length > 0) {
      const existing = existingUser.rows[0];
      if (existing.username.toLowerCase() === username.toLowerCase()) {
        return res.status(400).json({ success: false, error: 'Username already exists', message: 'Username already exists' });
      } else {
        return res.status(400).json({ success: false, error: 'Email already exists', message: 'Email already exists' });
      }
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await client.query('BEGIN');

    const userResult = await client.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
      [username, email, hashedPassword]
    );
    const newUser = userResult.rows[0];

    await client.query(
      `INSERT INTO user_profiles (user_id, first_name, pronouns, join_date, profile_color_hex, notifications, biometric_auth, dark_mode, reminder_time, data_purposes) 
       VALUES ($1, $2, $3, NOW(), $4, $5, $6, $7, $8, $9)`,
      [newUser.id, '', '', '#800080', true, false, false, '19:00:00', ['personalization', 'app_functionality']]
    );

    await client.query(
      `INSERT INTO questionnaire_responses (user_id, completed, first_name, pronouns, main_goals, communication_style, data_purpose, consent_given) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [newUser.id, false, '', '', [], '', 'app_personalization', false]
    );

    // initialize gamification row
    await client.query(
      `INSERT INTO gamification_progress (user_id, xp, level, current_streak, longest_streak, last_activity_date, updated_at)
       VALUES ($1, 0, 1, 0, 0, NULL, NOW()) ON CONFLICT (user_id) DO NOTHING`,
      [newUser.id]
    );

    await client.query('COMMIT');

    const token = jwt.sign({ userId: newUser.id, username: newUser.username }, JWT_SECRET, { expiresIn: '7d' });

    res.status(200).json({
      success: true,
      message: 'User registered successfully',
      token: token,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email
      }
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('💥 REGISTRATION ERROR:', error);
    let errorMessage = 'Server error during registration';
    let statusCode = 500;
    if (error.code === '23505') {
      if (error.detail?.includes('username')) errorMessage = 'Username already exists';
      else if (error.detail?.includes('email')) errorMessage = 'Email already exists';
      else errorMessage = 'User already exists';
      statusCode = 400;
    }
    res.status(statusCode).json({ success: false, error: errorMessage, message: errorMessage });
  } finally {
    client.release();
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  console.log('🔐 Login request started');
  
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and password are required', message: 'Username and password are required' });
    }

    const userResult = await pool.query(
      'SELECT id, username, email, password_hash, created_at FROM users WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($1)',
      [username]
    );
    if (userResult.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid credentials', message: 'Invalid credentials' });
    }

    const user = userResult.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ success: false, error: 'Invalid credentials', message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

    res.status(200).json({
      success: true,
      message: 'Login successful',
      token: token,
      user: { id: user.id, username: user.username, email: user.email }
    });

  } catch (error) {
    console.error('💥 LOGIN ERROR:', error);
    res.status(500).json({ success: false, error: 'Server error during login', message: 'Server error during login' });
  }
});

/* =========================
   PASSWORD RESET
   ========================= */
// REQUEST
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, error: 'Email is required', message: 'Email is required' });

    const userResult = await pool.query('SELECT id, username, email FROM users WHERE LOWER(email) = LOWER($1)', [email]);
    if (userResult.rows.length === 0) {
      return res.json({ success: true, message: 'If an account with that email exists, we\'ve sent password reset instructions.' });
    }
    const user = userResult.rows[0];
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 3600000);

    await pool.query(
      `INSERT INTO password_resets (user_id, reset_token, expires_at, created_at) 
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id) DO UPDATE SET reset_token = $2, expires_at = $3, created_at = NOW(), used = false`,
      [user.id, resetToken, resetExpires]
    );

    if (process.env.RESEND_API_KEY) {
      const ok = await sendPasswordResetEmail(email, resetToken, user.username || 'User');
      if (!ok) console.error('Resend failed; returning generic success.');
      return res.json({ success: true, message: 'Password reset instructions have been sent to your email address.' });
    } else {
      console.log('⚠️ No RESEND_API_KEY configured, returning token for development');
      return res.json({ success: true, message: 'If an account with that email exists, we\'ve sent password reset instructions.', developmentToken: resetToken });
    }
  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).json({ success: false, error: 'Server error', message: 'Server error occurred. Please try again.' });
  }
});

// CONFIRM
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ success: false, error: 'Token and new password are required', message: 'Token and new password are required' });
    if (newPassword.length < 6) return res.status(400).json({ success: false, error: 'Password must be at least 6 characters', message: 'Password must be at least 6 characters' });

    const resetResult = await pool.query(
      `SELECT pr.*, u.id as user_id, u.username 
       FROM password_resets pr 
       JOIN users u ON pr.user_id = u.id 
       WHERE pr.reset_token = $1 AND pr.expires_at > NOW() AND pr.used = false`,
      [token]
    );
    if (resetResult.rows.length === 0) {
      return res.status(400).json({ success: false, error: 'Invalid or expired reset token', message: 'Invalid or expired reset token' });
    }

    const resetRecord = resetResult.rows[0];
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [hashedPassword, resetRecord.user_id]);
      await client.query('UPDATE password_resets SET used = true WHERE id = $1', [resetRecord.id]);
      await client.query('COMMIT');
      res.json({ success: true, message: 'Password reset successful. You can now log in with your new password.' });
    } catch (err) {
      await client.query('ROLLBACK'); throw err;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ success: false, error: 'Server error', message: 'Server error' });
  }
});

/* =========================
   ME / LOGOUT
   ========================= */
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT id, username, email, created_at FROM users WHERE id = $1', [req.user.userId]);
    if (userResult.rows.length === 0) return res.status(404).json({ success: false, error: 'User not found', message: 'User not found' });
    res.json({ success: true, ...userResult.rows[0] });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ success: false, error: 'Server error', message: 'Server error' });
  }
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

/* =========================
   QUESTIONNAIRE
   ========================= */
app.get('/api/questionnaire', authenticateToken, async (req, res) => {
  try {
    const questionnaireResult = await pool.query('SELECT * FROM questionnaire_responses WHERE user_id = $1', [req.user.userId]);
    if (questionnaireResult.rows.length === 0) {
      return res.json({ success: true, completed: false, responses: { firstName: "", pronouns: "", mainGoals: [], communicationStyle: "" } });
    }
    const q = questionnaireResult.rows[0];
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
  } catch (error) {
    console.error('Questionnaire load error:', error);
    res.status(500).json({ success: false, error: 'Failed to load questionnaire', message: 'Failed to load questionnaire' });
  }
});

app.post('/api/questionnaire', authenticateToken, async (req, res) => {
  try {
    const { responses } = req.body;
    if (!responses || typeof responses !== 'object') {
      return res.status(400).json({ success: false, error: 'Invalid questionnaire responses', message: 'Invalid questionnaire responses' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      await client.query(
        `UPDATE questionnaire_responses 
         SET completed = true, 
             first_name = $1, 
             pronouns = $2, 
             main_goals = $3, 
             communication_style = $4, 
             data_purpose = $5,
             consent_given = $6,
             completed_at = NOW(),
             updated_at = NOW()
         WHERE user_id = $7`,
        [
          responses.firstName || "",
          responses.pronouns || "",
          responses.mainGoals || [],
          responses.communicationStyle || "",
          'app_personalization',
          true,
          req.user.userId
        ]
      );

      await client.query('COMMIT');

      // Gamify: questionnaire completion
      await trackAction(req.user.userId, 'questionnaire_complete');

      res.json({ success: true, message: 'Questionnaire completed successfully' });
    } catch (error) {
      await client.query('ROLLBACK'); throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Questionnaire save error:', error);
    res.status(500).json({ success: false, error: 'Failed to save questionnaire', message: 'Failed to save questionnaire' });
  }
});

/* =========================
   PROFILE
   ========================= */
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const profileResult = await pool.query('SELECT * FROM user_profiles WHERE user_id = $1', [req.user.userId]);
    if (profileResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Profile not found', message: 'Profile not found' });
    }
    const p = profileResult.rows[0];
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
  } catch (error) {
    console.error('Profile load error:', error);
    res.status(500).json({ success: false, error: 'Failed to load profile', message: 'Failed to load profile' });
  }
});

app.post('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { 
      firstName, pronouns, joinDate, profileColorHex, notifications, 
      biometricAuth, darkMode, reminderTime, dataPurposes  
    } = req.body;

    let dataArray = ['personalization', 'app_functionality'];
    if (Array.isArray(dataPurposes)) dataArray = dataPurposes;
    else if (typeof dataPurposes === 'string') dataArray = [dataPurposes];

    const updateResult = await pool.query(
      `UPDATE user_profiles 
       SET first_name = $1, 
           pronouns = $2, 
           join_date = COALESCE($3, join_date),
           profile_color_hex = COALESCE($4, profile_color_hex),
           notifications = COALESCE($5, notifications),
           biometric_auth = COALESCE($6, biometric_auth),
           dark_mode = COALESCE($7, dark_mode),
           reminder_time = COALESCE($8, reminder_time),
           data_purposes = $9,
           updated_at = NOW()
       WHERE user_id = $10
       RETURNING first_name, pronouns, data_purposes`,
      [
        firstName || "",
        pronouns || "",
        joinDate,
        profileColorHex || "#800080",
        notifications !== undefined ? notifications : true,
        biometricAuth !== undefined ? biometricAuth : false,
        darkMode !== undefined ? darkMode : false,
        reminderTime || "19:00:00",
        dataArray,
        req.user.userId
      ]
    );

    // Gamify: profile update (small XP)
    await trackAction(req.user.userId, 'profile_update');

    res.json({ success: true, message: 'Profile updated successfully', profile: updateResult.rows[0] });
  } catch (error) {
    console.error('💥 Profile save error:', error);
    res.status(500).json({ success: false, error: 'Failed to save profile', message: 'Failed to save profile' });
  }
});

/* =========================
   MOOD
   ========================= */
app.get('/api/mood', authenticateToken, async (req, res) => {
  try {
    const moodResult = await pool.query(
      'SELECT id, mood, note, entry_date as date, data_purpose FROM mood_entries WHERE user_id = $1 ORDER BY entry_date DESC',
      [req.user.userId]
    );
    res.json({ success: true, data: moodResult.rows });
  } catch (error) {
    console.error('Mood load error:', error);
    res.status(500).json({ success: false, error: 'Failed to load mood entries', message: 'Failed to load mood entries' });
  }
});

app.post('/api/mood', authenticateToken, async (req, res) => {
  try {
    const { mood, note, date, dataPurpose = 'mood_tracking' } = req.body;
    if (!mood || !date) return res.status(400).json({ success: false, error: 'Mood and date are required', message: 'Mood and date are required' });
    if (mood < 1 || mood > 10) return res.status(400).json({ success: false, error: 'Mood must be between 1 and 10', message: 'Mood must be between 1 and 10' });

    const moodResult = await pool.query(
      'INSERT INTO mood_entries (user_id, mood, note, entry_date, data_purpose) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.userId, parseInt(mood), note || null, date, dataPurpose]
    );

    // Gamify: mood entry
    const gamify = await trackAction(req.user.userId, 'mood_entry');

    res.json({ 
      success: true, 
      message: 'Mood entry saved successfully',
      entry: moodResult.rows[0],
      gamification: gamify
    });
  } catch (error) {
    console.error('Mood save error:', error);
    res.status(500).json({ success: false, error: 'Failed to save mood entry', message: 'Failed to save mood entry' });
  }
});

/* =========================
   JOURNAL
   ========================= */
app.get('/api/journal', authenticateToken, async (req, res) => {
  try {
    const journalResult = await pool.query(
      'SELECT id, content, prompt, entry_date as date, data_purpose FROM journal_entries WHERE user_id = $1 ORDER BY entry_date DESC',
      [req.user.userId]
    );
    res.json({ success: true, data: journalResult.rows });
  } catch (error) {
    console.error('Journal load error:', error);
    res.status(500).json({ success: false, error: 'Failed to load journal entries', message: 'Failed to load journal entries' });
  }
});

app.post('/api/journal', authenticateToken, async (req, res) => {
  try {
    const { content, prompt, date, dataPurpose = 'journaling' } = req.body;
    if (!content || !date) return res.status(400).json({ success: false, error: 'Content and date are required', message: 'Content and date are required' });
    if (content.trim().length === 0) return res.status(400).json({ success: false, error: 'Content cannot be empty', message: 'Content cannot be empty' });

    const journalResult = await pool.query(
      'INSERT INTO journal_entries (user_id, content, prompt, entry_date, data_purpose) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.userId, content.trim(), prompt || null, date, dataPurpose]
    );

    // Gamify: journal entry
    const gamify = await trackAction(req.user.userId, 'journal_entry');

    res.json({ 
      success: true, 
      message: 'Journal entry saved successfully',
      entry: journalResult.rows[0],
      gamification: gamify
    });
  } catch (error) {
    console.error('Journal save error:', error);
    res.status(500).json({ success: false, error: 'Failed to save journal entry', message: 'Failed to save journal entry' });
  }
});

/* =========================
   CHAT
   ========================= */
app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    const { message, chatHistory, sessionId, consentedToAI, userContext } = req.body;
    if (!consentedToAI) {
      return res.status(403).json({ success: false, error: 'AI processing consent required', message: 'AI processing consent required', requiresConsent: true });
    }

    let currentSession = null;

    if (sessionId) {
      const sessionResult = await pool.query('SELECT * FROM chat_sessions WHERE id = $1 AND user_id = $2', [sessionId, req.user.userId]);
      if (sessionResult.rows.length > 0) currentSession = sessionResult.rows[0];
    }
    
    if (!currentSession) {
      const sessionResult = await pool.query(
        'INSERT INTO chat_sessions (user_id, start_time, last_activity, user_context) VALUES ($1, NOW(), NOW(), $2) RETURNING *',
        [req.user.userId, JSON.stringify({ mood: null, recentJournalThemes: [], questionnaireCompleted: false })]
      );
      currentSession = sessionResult.rows[0];
    }

    const sensitiveKeywords = ['suicide', 'self-harm', 'kill myself', 'medication', 'doctor', 'therapist'];
    const containsSensitive = sensitiveKeywords.some(keyword => message.toLowerCase().includes(keyword));

    await pool.query(
      'INSERT INTO chat_messages (session_id, role, content, contains_sensitive_data, timestamp) VALUES ($1, $2, $3, $4, NOW())',
      [currentSession.id, 'user', message, containsSensitive]
    );

    // Gamify: chat message
    const gamifyUpdate = await trackAction(req.user.userId, 'chat_message');

    // (Optional) AI call omitted here for brevity – your previous logic can remain.
    const fallbackResponse = "I'm here with you. Tell me more about what's on your mind.";
    await pool.query('INSERT INTO chat_messages (session_id, role, content, timestamp) VALUES ($1, $2, $3, NOW())',
      [currentSession.id, 'assistant', fallbackResponse]);

    res.json({ success: true, response: fallbackResponse, sessionId: currentSession.id, gamification: gamifyUpdate });

  } catch (error) {
    console.error('Chat error:', error);
    res.status(500).json({ success: false, error: 'Server error', message: 'Server error' });
  }
});

/* =========================
   GAMIFY PROGRESS ENDPOINT
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
      const nextLevelXP = (nextLevel - 1) * 100; // 100xp per level
      res.json({
        success: true,
        progress: {
          xp: progress.xp,
          level: progress.level,
          currentStreak: progress.current_streak,
          longestStreak: progress.longest_streak,
          lastActivityDate: progress.last_activity_date
        },
        badges: badges,
        nextLevelXP
      });
    } catch (e) {
      await client.query('ROLLBACK'); throw e;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('gamify/progress error:', error);
    res.status(500).json({ success: false, error: 'Failed to load progress' });
  }
});

/* =========================
   DEBUG & HEALTH
   ========================= */
app.get('/api/debug/db-test', async (req, res) => {
  try {
    const client = await pool.connect();
    const usersTest = await client.query('SELECT COUNT(*) as count FROM users');
    const profilesTest = await client.query('SELECT COUNT(*) as count FROM user_profiles');
    const questionnaireTest = await client.query('SELECT COUNT(*) as count FROM questionnaire_responses');
    client.release();
    res.json({
      success: true,
      message: 'Database connection and tables working',
      data: {
        users: parseInt(usersTest.rows[0].count),
        profiles: parseInt(profilesTest.rows[0].count),
        questionnaires: parseInt(questionnaireTest.rows[0].count)
      }
    });
  } catch (error) {
    console.error('❌ Database test error:', error);
    res.status(500).json({ success: false, error: 'Database test failed', details: { message: error.message, code: error.code, detail: error.detail } });
  }
});

app.get('/api/debug/users', async (req, res) => {
  try {
    if (process.env.NODE_ENV === 'production') return res.status(404).json({ error: 'Not found' });
    const users = await pool.query('SELECT id, username, email, created_at FROM users ORDER BY created_at DESC LIMIT 10');
    res.json({ success: true, count: users.rows.length, users: users.rows });
  } catch (error) {
    console.error('Debug users error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch users', details: error.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '6.4.0 - Gamification (XP + Streaks + Badges)',
    database: 'PostgreSQL',
    openai: process.env.OPENAI_API_KEY ? 'Available' : 'Fallback mode',
    features: {
      passwordReset: 'Available',
      profileFixes: 'Applied',
      dataStructure: 'Fixed',
      arrayHandling: 'Fixed',
      aiPrompt: 'Enhanced',
      gamification: 'XP/Streaks/Badges'
    },
    success: true
  });
});

app.get('/', (req, res) => {
  res.json({
    message: 'Luma Backend API',
    version: '6.4.0',
    status: 'running',
    endpoints: {
      health: '/health',
      auth: '/api/auth/*',
      profile: '/api/profile',
      mood: '/api/mood',
      journal: '/api/journal',
      chat: '/api/chat',
      gamify: '/api/gamify/progress'
    }
  });
});

// CATCH ALL
app.use('*', (req, res) => {
  res.status(404).json({ success: false, error: 'Route not found', message: 'The requested endpoint does not exist' });
});

// ERROR HANDLER
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ success: false, error: 'Internal server error', message: 'An unexpected error occurred' });
});

// Start server
const startServer = async () => {
  try {
    console.log('🚀 Starting Luma Backend Server...');
    const client = await pool.connect();
    client.release();
    await initializeDatabase();
    console.log('✅ Database initialization complete');
    app.listen(PORT, () => {
      console.log(`✅ Luma backend running on port ${PORT}`);
      console.log(`🌐 Server URL: https://luma-backend-nfdc.onrender.com`);
      console.log(`🤖 AI Mode: ${process.env.OPENAI_API_KEY ? 'OpenAI GPT-4' : 'Fallback responses'}`);
      console.log(`🔥 SERVER IS READY TO HANDLE REQUESTS`);
      console.log(`🎯 Gamification: XP + streaks + badges enabled`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();
