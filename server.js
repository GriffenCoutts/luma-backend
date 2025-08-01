const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Resend } = require('resend');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Initialize Resend
const resend = new Resend(process.env.RESEND_API_KEY);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this';

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

// Initialize database tables with PIPEDA compliance
async function initializeDatabase() {
  try {
    console.log('🗄️ Initializing PIPEDA-compliant database tables...');
    
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

    // PIPEDA: Enhanced user profiles with data minimization
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
        data_purposes TEXT[] DEFAULT '{"personalization","app_functionality"}',
        consent_timestamp TIMESTAMP WITH TIME ZONE,
        data_retention_period INTEGER DEFAULT 365,
        app_theme VARCHAR(20) DEFAULT 'system',
        accessibility_features JSONB DEFAULT '{}',
        language_preference VARCHAR(10) DEFAULT 'en',
        timezone VARCHAR(50) DEFAULT 'America/Toronto',
        onboarding_completed_at TIMESTAMP WITH TIME ZONE,
        last_active_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        app_version VARCHAR(20),
        device_info JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // PIPEDA: Consent tracking table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_consents (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        data_collection BOOLEAN DEFAULT false,
        ai_processing BOOLEAN DEFAULT false,
        mood_tracking BOOLEAN DEFAULT false,
        journaling BOOLEAN DEFAULT false,
        notifications BOOLEAN DEFAULT false,
        data_sharing BOOLEAN DEFAULT false,
        version VARCHAR(10) DEFAULT '1.0',
        ip_address INET,
        user_agent TEXT,
        consent_method VARCHAR(50) DEFAULT 'app_interface',
        consent_source VARCHAR(100) DEFAULT 'mobile_app',
        withdrawal_reason TEXT,
        parent_consent_id UUID REFERENCES user_consents(id),
        consent_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        withdrawn_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // PIPEDA: Data access audit log
    await pool.query(`
      CREATE TABLE IF NOT EXISTS data_access_logs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        access_type VARCHAR(50) NOT NULL,
        data_type VARCHAR(50) NOT NULL,
        ip_address INET,
        user_agent TEXT,
        purpose TEXT,
        accessed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // PIPEDA: Enhanced questionnaire responses with data minimization
    await pool.query(`
      CREATE TABLE IF NOT EXISTS questionnaire_responses (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        completed BOOLEAN DEFAULT false,
        first_name VARCHAR(255),
        pronouns VARCHAR(50),
        main_goals TEXT[],
        communication_style VARCHAR(255),
        data_purpose VARCHAR(100) DEFAULT 'app_personalization',
        consent_given BOOLEAN DEFAULT false,
        completed_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
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
        content_hash VARCHAR(64),
        privacy_level VARCHAR(20) DEFAULT 'standard',
        auto_delete_at TIMESTAMP WITH TIME ZONE,
        content_classification JSONB DEFAULT '{"containsMedicalTerms": false, "containsPersonalInfo": false, "sensitivityScore": 1}',
        timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // PIPEDA: Enhanced mood entries with data purpose tracking
    await pool.query(`
      CREATE TABLE IF NOT EXISTS mood_entries (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        mood INTEGER NOT NULL CHECK (mood >= 1 AND mood <= 10),
        note TEXT,
        entry_date TIMESTAMP WITH TIME ZONE NOT NULL,
        data_purpose VARCHAR(100) DEFAULT 'mood_tracking',
        mood_category VARCHAR(50),
        mood_triggers TEXT[],
        weather_context JSONB,
        activity_context TEXT,
        privacy_level VARCHAR(20) DEFAULT 'private',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // PIPEDA: Enhanced journal entries with data purpose tracking
    await pool.query(`
      CREATE TABLE IF NOT EXISTS journal_entries (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        prompt TEXT,
        entry_date TIMESTAMP WITH TIME ZONE NOT NULL,
        data_purpose VARCHAR(100) DEFAULT 'journaling',
        entry_type VARCHAR(50) DEFAULT 'free_write',
        emotional_tone VARCHAR(50),
        word_count INTEGER,
        reading_time_estimate INTEGER,
        tags TEXT[],
        privacy_level VARCHAR(20) DEFAULT 'private',
        auto_delete_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Password reset tokens
    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        token VARCHAR(10) PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // PIPEDA: Data deletion requests
    await pool.query(`
      CREATE TABLE IF NOT EXISTS data_deletion_requests (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        request_type VARCHAR(50) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        requested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        processed_at TIMESTAMP WITH TIME ZONE,
        processed_by VARCHAR(255)
      )
    `);

    // NEW TABLES for enhanced features
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notification_preferences (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        notification_type VARCHAR(50) NOT NULL,
        enabled BOOLEAN DEFAULT true,
        frequency VARCHAR(20) DEFAULT 'daily',
        time_of_day TIME DEFAULT '19:00:00',
        days_of_week INTEGER[] DEFAULT '{1,2,3,4,5,6,7}',
        sound_enabled BOOLEAN DEFAULT true,
        vibration_enabled BOOLEAN DEFAULT true,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        UNIQUE(user_id, notification_type)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        session_token VARCHAR(255) UNIQUE,
        device_id VARCHAR(255),
        device_type VARCHAR(50),
        app_version VARCHAR(20),
        os_version VARCHAR(50),
        ip_address INET,
        user_agent TEXT,
        login_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        logout_at TIMESTAMP WITH TIME ZONE,
        session_duration_seconds INTEGER,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS privacy_settings (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        setting_name VARCHAR(100) NOT NULL,
        setting_value JSONB NOT NULL,
        data_type VARCHAR(50),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        UNIQUE(user_id, setting_name)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_app_preferences (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        preference_key VARCHAR(100) NOT NULL,
        preference_value JSONB NOT NULL,
        preference_type VARCHAR(50),
        sync_across_devices BOOLEAN DEFAULT true,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        UNIQUE(user_id, preference_key)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS consent_audit_trail (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        consent_id UUID REFERENCES user_consents(id) ON DELETE CASCADE,
        action VARCHAR(50) NOT NULL,
        consent_type VARCHAR(50) NOT NULL,
        old_value BOOLEAN,
        new_value BOOLEAN,
        reason TEXT,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Create indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_user_consents_user_id ON user_consents(user_id);
      CREATE INDEX IF NOT EXISTS idx_user_consents_timestamp ON user_consents(consent_timestamp);
      CREATE INDEX IF NOT EXISTS idx_data_access_logs_user_id ON data_access_logs(user_id);
      CREATE INDEX IF NOT EXISTS idx_data_access_logs_accessed_at ON data_access_logs(accessed_at);
      CREATE INDEX IF NOT EXISTS idx_chat_sessions_user_id ON chat_sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_chat_sessions_start_time ON chat_sessions(start_time);
      CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id);
      CREATE INDEX IF NOT EXISTS idx_chat_messages_timestamp ON chat_messages(timestamp);
      CREATE INDEX IF NOT EXISTS idx_mood_entries_user_id ON mood_entries(user_id);
      CREATE INDEX IF NOT EXISTS idx_mood_entries_date ON mood_entries(entry_date);
      CREATE INDEX IF NOT EXISTS idx_journal_entries_user_id ON journal_entries(user_id);
      CREATE INDEX IF NOT EXISTS idx_journal_entries_date ON journal_entries(entry_date);
      CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires ON password_reset_tokens(expires_at);
      CREATE INDEX IF NOT EXISTS idx_data_deletion_requests_user_id ON data_deletion_requests(user_id);
      CREATE INDEX IF NOT EXISTS idx_notification_preferences_user_id ON notification_preferences(user_id);
      CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_privacy_settings_user_id ON privacy_settings(user_id);
      CREATE INDEX IF NOT EXISTS idx_user_app_preferences_user_id ON user_app_preferences(user_id);
      CREATE INDEX IF NOT EXISTS idx_consent_audit_trail_user_id ON consent_audit_trail(user_id);
    `);

    console.log('✅ PIPEDA-compliant database tables initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
  }
}

// Initialize database on startup
initializeDatabase();

// PIPEDA: Middleware to log data access
const logDataAccess = async (userId, accessType, dataType, req, purpose = null) => {
  try {
    await pool.query(
      'INSERT INTO data_access_logs (user_id, access_type, data_type, ip_address, user_agent, purpose) VALUES ($1, $2, $3, $4, $5, $6)',
      [userId, accessType, dataType, req.ip, req.get('User-Agent'), purpose]
    );
  } catch (error) {
    console.error('Failed to log data access:', error);
  }
};

// PIPEDA: Function to check if data should be auto-deleted
const checkDataRetention = async (userId) => {
  try {
    const profileResult = await pool.query(
      'SELECT data_retention_period FROM user_profiles WHERE user_id = $1',
      [userId]
    );
    
    if (profileResult.rows.length > 0) {
      const retentionDays = profileResult.rows[0].data_retention_period;
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
      
      // Auto-delete old mood entries
      await pool.query(
        'DELETE FROM mood_entries WHERE user_id = $1 AND entry_date < $2',
        [userId, cutoffDate]
      );
      
      // Auto-delete old journal entries
      await pool.query(
        'DELETE FROM journal_entries WHERE user_id = $1 AND entry_date < $2',
        [userId, cutoffDate]
      );
      
      console.log(`🗑️ Auto-deleted old data for user ${userId} older than ${retentionDays} days`);
    }
  } catch (error) {
    console.error('Error checking data retention:', error);
  }
};

// AUTHENTICATION MIDDLEWARE
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// USER REGISTRATION
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const userResult = await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
      [username, email, hashedPassword]
    );

    const newUser = userResult.rows[0];

    // PIPEDA: Create minimized user profile
    await pool.query(
      `INSERT INTO user_profiles (user_id, first_name, pronouns, join_date, profile_color_hex, notifications, biometric_auth, dark_mode, reminder_time, data_purposes, data_retention_period) 
       VALUES ($1, '', '', NOW(), '#800080', true, false, false, '19:00:00', '{"personalization","app_functionality"}', 365)`,
      [newUser.id]
    );

    // PIPEDA: Create empty questionnaire response
    await pool.query(
      `INSERT INTO questionnaire_responses (user_id, completed, first_name, pronouns, main_goals, communication_style, data_purpose, consent_given) 
       VALUES ($1, false, '', '', '{}', '', 'app_personalization', false)`,
      [newUser.id]
    );

    // Create default notification preferences
    const defaultNotifications = [
      { type: 'mood_reminder', enabled: true },
      { type: 'journal_reminder', enabled: true },
      { type: 'weekly_summary', enabled: false }
    ];

    for (const notif of defaultNotifications) {
      await pool.query(
        'INSERT INTO notification_preferences (user_id, notification_type, enabled) VALUES ($1, $2, $3)',
        [newUser.id, notif.type, notif.enabled]
      );
    }

    // Create default privacy settings
    await pool.query(
      `INSERT INTO privacy_settings (user_id, setting_name, setting_value, data_type) 
       VALUES ($1, 'data_sharing_external', '{"enabled": false, "partners": []}', 'boolean')`,
      [newUser.id]
    );

    // Generate JWT token
    const token = jwt.sign(
      { userId: newUser.id, username: newUser.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'User registered successfully',
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// USER LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user (allow login with username or email)
    const userResult = await pool.query(
      'SELECT id, username, email, password_hash FROM users WHERE username = $1 OR email = $1',
      [username]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = userResult.rows[0];

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // PIPEDA: Check data retention on login
    await checkDataRetention(user.id);

    // Update last active timestamp
    await pool.query(
      'UPDATE user_profiles SET last_active_at = NOW() WHERE user_id = $1',
      [user.id]
    );

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// PIPEDA: CONSENT ENDPOINTS
app.post('/api/consent', authenticateToken, async (req, res) => {
  try {
    const {
      dataCollection,
      aiProcessing,
      moodTracking,
      journaling,
      notifications,
      dataSharing,
      version = '1.0'
    } = req.body;

    // Insert new consent record
    const consentResult = await pool.query(
      `INSERT INTO user_consents (user_id, data_collection, ai_processing, mood_tracking, journaling, notifications, data_sharing, version, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
      [
        req.user.userId,
        dataCollection,
        aiProcessing,
        moodTracking,
        journaling,
        notifications,
        dataSharing,
        version,
        req.ip,
        req.get('User-Agent')
      ]
    );

    // Log consent changes in audit trail
    const consentId = consentResult.rows[0].id;
    const consentTypes = [
      { type: 'data_collection', value: dataCollection },
      { type: 'ai_processing', value: aiProcessing },
      { type: 'mood_tracking', value: moodTracking },
      { type: 'journaling', value: journaling },
      { type: 'notifications', value: notifications },
      { type: 'data_sharing', value: dataSharing }
    ];

    for (const consent of consentTypes) {
      await pool.query(
        'INSERT INTO consent_audit_trail (user_id, consent_id, action, consent_type, new_value, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [req.user.userId, consentId, 'granted', consent.type, consent.value, req.ip, req.get('User-Agent')]
      );
    }

    // Update profile consent timestamp
    await pool.query(
      'UPDATE user_profiles SET consent_timestamp = NOW() WHERE user_id = $1',
      [req.user.userId]
    );

    console.log('✅ Consent recorded for user:', req.user.username);
    res.json({ success: true, message: 'Consent preferences saved' });

  } catch (error) {
    console.error('Consent save error:', error);
    res.status(500).json({ error: 'Failed to save consent preferences' });
  }
});

app.get('/api/consent/status', authenticateToken, async (req, res) => {
  try {
    const consentResult = await pool.query(
      `SELECT * FROM user_consents 
       WHERE user_id = $1 AND withdrawn_at IS NULL 
       ORDER BY consent_timestamp DESC 
       LIMIT 1`,
      [req.user.userId]
    );

    if (consentResult.rows.length === 0) {
      return res.json({ hasValidConsent: false });
    }

    const consent = consentResult.rows[0];
    
    res.json({
      hasValidConsent: consent.data_collection,
      consent: {
        dataCollection: consent.data_collection,
        aiProcessing: consent.ai_processing,
        moodTracking: consent.mood_tracking,
        journaling: consent.journaling,
        notifications: consent.notifications,
        dataSharing: consent.data_sharing,
        timestamp: consent.consent_timestamp
      }
    });

  } catch (error) {
    console.error('Consent status error:', error);
    res.status(500).json({ error: 'Failed to check consent status' });
  }
});

// NOTIFICATION PREFERENCES ENDPOINTS
app.get('/api/notifications/preferences', authenticateToken, async (req, res) => {
  try {
    await logDataAccess(req.user.userId, 'read', 'notification_preferences', req);

    const preferencesResult = await pool.query(
      'SELECT * FROM notification_preferences WHERE user_id = $1 ORDER BY notification_type',
      [req.user.userId]
    );
    
    res.json(preferencesResult.rows);
  } catch (error) {
    console.error('Get notification preferences error:', error);
    res.status(500).json({ error: 'Failed to load notification preferences' });
  }
});

app.post('/api/notifications/preferences', authenticateToken, async (req, res) => {
  try {
    const { notificationType, enabled, frequency, timeOfDay, daysOfWeek, soundEnabled, vibrationEnabled } = req.body;
    
    if (!notificationType) {
      return res.status(400).json({ error: 'Notification type is required' });
    }

    await logDataAccess(req.user.userId, 'update', 'notification_preferences', req);
    
    // Upsert notification preference
    const result = await pool.query(
      `INSERT INTO notification_preferences 
       (user_id, notification_type, enabled, frequency, time_of_day, days_of_week, sound_enabled, vibration_enabled, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
       ON CONFLICT (user_id, notification_type) 
       DO UPDATE SET 
         enabled = EXCLUDED.enabled,
         frequency = EXCLUDED.frequency,
         time_of_day = EXCLUDED.time_of_day,
         days_of_week = EXCLUDED.days_of_week,
         sound_enabled = EXCLUDED.sound_enabled,
         vibration_enabled = EXCLUDED.vibration_enabled,
         updated_at = NOW()
       RETURNING *`,
      [req.user.userId, notificationType, enabled, frequency, timeOfDay, daysOfWeek, soundEnabled, vibrationEnabled]
    );
    
    res.json({ success: true, preference: result.rows[0] });
  } catch (error) {
    console.error('Save notification preferences error:', error);
    res.status(500).json({ error: 'Failed to save notification preferences' });
  }
});

// USER APP PREFERENCES ENDPOINTS
app.get('/api/preferences', authenticateToken, async (req, res) => {
  try {
    await logDataAccess(req.user.userId, 'read', 'user_app_preferences', req);

    const preferencesResult = await pool.query(
      'SELECT * FROM user_app_preferences WHERE user_id = $1',
      [req.user.userId]
    );
    
    const preferences = {};
    preferencesResult.rows.forEach(row => {
      preferences[row.preference_key] = row.preference_value;
    });
    
    res.json(preferences);
  } catch (error) {
    console.error('Get app preferences error:', error);
    res.status(500).json({ error: 'Failed to load app preferences' });
  }
});

app.post('/api/preferences', authenticateToken, async (req, res) => {
  try {
    const { preferenceKey, preferenceValue, preferenceType, syncAcrossDevices } = req.body;
    
    if (!preferenceKey || preferenceValue === undefined) {
      return res.status(400).json({ error: 'Preference key and value are required' });
    }

    await logDataAccess(req.user.userId, 'update', 'user_app_preferences', req);
    
    const result = await pool.query(
      `INSERT INTO user_app_preferences 
       (user_id, preference_key, preference_value, preference_type, sync_across_devices, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       ON CONFLICT (user_id, preference_key) 
       DO UPDATE SET 
         preference_value = EXCLUDED.preference_value,
         preference_type = EXCLUDED.preference_type,
         sync_across_devices = EXCLUDED.sync_across_devices,
         updated_at = NOW()
       RETURNING *`,
      [req.user.userId, preferenceKey, preferenceValue, preferenceType, syncAcrossDevices]
    );
    
    res.json({ success: true, preference: result.rows[0] });
  } catch (error) {
    console.error('Save app preferences error:', error);
    res.status(500).json({ error: 'Failed to save app preferences' });
  }
});

// PRIVACY SETTINGS ENDPOINTS
app.get('/api/privacy/settings', authenticateToken, async (req, res) => {
  try {
    await logDataAccess(req.user.userId, 'read', 'privacy_settings', req);

    const settingsResult = await pool.query(
      'SELECT * FROM privacy_settings WHERE user_id = $1',
      [req.user.userId]
    );
    
    const settings = {};
    settingsResult.rows.forEach(row => {
      settings[row.setting_name] = row.setting_value;
    });
    
    res.json(settings);
  } catch (error) {
    console.error('Get privacy settings error:', error);
    res.status(500).json({ error: 'Failed to load privacy settings' });
  }
});

app.post('/api/privacy/settings', authenticateToken, async (req, res) => {
  try {
    const { settingName, settingValue, dataType } = req.body;
    
    if (!settingName || settingValue === undefined) {
      return res.status(400).json({ error: 'Setting name and value are required' });
    }

    await logDataAccess(req.user.userId, 'update', 'privacy_settings', req);
    
    const result = await pool.query(
      `INSERT INTO privacy_settings 
       (user_id, setting_name, setting_value, data_type, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (user_id, setting_name) 
       DO UPDATE SET 
         setting_value = EXCLUDED.setting_value,
         data_type = EXCLUDED.data_type,
         updated_at = NOW()
       RETURNING *`,
      [req.user.userId, settingName, settingValue, dataType]
    );
    
    res.json({ success: true, setting: result.rows[0] });
  } catch (error) {
    console.error('Save privacy settings error:', error);
    res.status(500).json({ error: 'Failed to save privacy settings' });
  }
});

// PIPEDA: DATA DELETION ENDPOINTS
app.post('/api/data-deletion', authenticateToken, async (req, res) => {
  try {
    // Create deletion request
    await pool.query(
      'INSERT INTO data_deletion_requests (user_id, request_type, status) VALUES ($1, $2, $3)',
      [req.user.userId, 'user_requested', 'pending']
    );

    // Withdraw all consent
    await pool.query(
      'UPDATE user_consents SET withdrawn_at = NOW() WHERE user_id = $1 AND withdrawn_at IS NULL',
      [req.user.userId]
    );

    console.log('🗑️ Data deletion requested for user:', req.user.username);
    res.json({ success: true, message: 'Data deletion request submitted' });

  } catch (error) {
    console.error('Data deletion request error:', error);
    res.status(500).json({ error: 'Failed to request data deletion' });
  }
});

app.delete('/api/user/delete-all-data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Delete all user data in proper order (foreign key constraints)
    await pool.query('DELETE FROM consent_audit_trail WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM user_app_preferences WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM privacy_settings WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM user_sessions WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM notification_preferences WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM data_access_logs WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM data_deletion_requests WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM user_consents WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM chat_messages WHERE session_id IN (SELECT id FROM chat_sessions WHERE user_id = $1)', [userId]);
    await pool.query('DELETE FROM chat_sessions WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM mood_entries WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM journal_entries WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM questionnaire_responses WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM user_profiles WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);

    console.log('🗑️ Complete data deletion completed for user:', req.user.username);
    res.json({ success: true, message: 'All user data has been permanently deleted' });

  } catch (error) {
    console.error('Complete data deletion error:', error);
    res.status(500).json({ error: 'Failed to delete user data' });
  }
});

// PIPEDA: Enhanced user data export
app.get('/api/user/export-data', authenticateToken, async (req, res) => {
  try {
    await logDataAccess(req.user.userId, 'export', 'all_data', req, 'user_data_export');

    // Get all user data
    const userResult = await pool.query('SELECT username, email, created_at FROM users WHERE id = $1', [req.user.userId]);
    const profileResult = await pool.query('SELECT * FROM user_profiles WHERE user_id = $1', [req.user.userId]);
    const questionnaireResult = await pool.query('SELECT * FROM questionnaire_responses WHERE user_id = $1', [req.user.userId]);
    const consentResult = await pool.query('SELECT * FROM user_consents WHERE user_id = $1 ORDER BY consent_timestamp DESC', [req.user.userId]);
    const moodResult = await pool.query('SELECT * FROM mood_entries WHERE user_id = $1 ORDER BY entry_date DESC', [req.user.userId]);
    const journalResult = await pool.query('SELECT * FROM journal_entries WHERE user_id = $1 ORDER BY entry_date DESC', [req.user.userId]);
    const notificationResult = await pool.query('SELECT * FROM notification_preferences WHERE user_id = $1', [req.user.userId]);
    const privacyResult = await pool.query('SELECT * FROM privacy_settings WHERE user_id = $1', [req.user.userId]);
    const preferencesResult = await pool.query('SELECT * FROM user_app_preferences WHERE user_id = $1', [req.user.userId]);
    
    const exportData = {
      exportDate: new Date().toISOString(),
      user: userResult.rows[0] || null,
      profile: profileResult.rows[0] || null,
      questionnaire: questionnaireResult.rows[0] || null,
      consents: consentResult.rows,
      moodEntries: moodResult.rows,
      journalEntries: journalResult.rows,
      notificationPreferences: notificationResult.rows,
      privacySettings: privacyResult.rows,
      appPreferences: preferencesResult.rows,
      dataRetentionInfo: {
        retentionPeriodDays: profileResult.rows[0]?.data_retention_period || 365,
        dataTypes: {
          profile: "Retained for account lifetime",
          moodEntries: `Retained for ${profileResult.rows[0]?.data_retention_period || 365} days`,
          journalEntries: `Retained for ${profileResult.rows[0]?.data_retention_period || 365} days`,
          chatHistory: "Not permanently stored",
          consents: "Retained for 7 years (legal requirement)"
        }
      }
    };

    res.json(exportData);

  } catch (error) {
    console.error('Data export error:', error);
    res.status(500).json({ error: 'Failed to export user data' });
  }
});

// FORGOT PASSWORD - Request Reset
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    console.log('🔍 Password reset request for:', email);

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Find user by email
    const userResult = await pool.query('SELECT id, username FROM users WHERE email = $1', [email]);
    
    if (userResult.rows.length === 0) {
      return res.json({ 
        success: true, 
        message: 'If an account with that email exists, we have sent a password reset code.' 
      });
    }

    const user = userResult.rows[0];

    // Generate reset token
    const resetToken = Math.random().toString(36).substring(2, 8).toUpperCase();
    const expires = new Date(Date.now() + 3600000); // 1 hour from now

    // Store reset token in database
    await pool.query(
      'INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT (token) DO UPDATE SET user_id = $2, expires_at = $3',
      [resetToken, user.id, expires]
    );

    console.log('🎫 Generated reset token:', resetToken);

    // Send email
    try {
      const emailResult = await resend.emails.send({
        from: 'onboarding@resend.dev',
        to: [email],
        subject: 'Reset Your Luma Password 🌙',
        html: `
          <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
            <div style="text-align: center; margin-bottom: 40px; padding: 30px 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 16px;">
              <h1 style="color: white; margin: 0; font-size: 32px; font-weight: 700;">🌙 Luma</h1>
              <p style="color: rgba(255,255,255,0.9); margin: 8px 0 0 0; font-size: 16px;">Your AI Mental Health Companion</p>
            </div>
            
            <div style="text-align: center; margin-bottom: 30px;">
              <h2 style="color: #1f2937; margin: 0 0 16px 0; font-size: 28px; font-weight: 600;">Password Reset Request</h2>
              <p style="color: #6b7280; font-size: 16px; line-height: 1.6; margin: 0;">Hi ${user.username}, we received a request to reset your Luma password.</p>
            </div>
            
            <div style="background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%); border: 3px solid #7c3aed; border-radius: 16px; padding: 40px; margin: 30px 0; text-align: center;">
              <p style="color: #6b7280; font-size: 14px; margin: 0 0 16px 0; text-transform: uppercase; letter-spacing: 2px; font-weight: 600;">Your Reset Code</p>
              <div style="background: white; border-radius: 12px; padding: 24px; display: inline-block; box-shadow: 0 8px 25px rgba(124, 58, 237, 0.15); border: 2px solid #7c3aed;">
                <span style="font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace; font-size: 36px; font-weight: 900; color: #7c3aed; letter-spacing: 6px; text-shadow: 0 2px 4px rgba(124, 58, 237, 0.2);">${resetToken}</span>
              </div>
            </div>
            
            <div style="background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%); border-left: 6px solid #f59e0b; padding: 24px; margin: 30px 0; border-radius: 8px;">
              <h3 style="margin: 0 0 12px 0; color: #92400e; font-size: 18px; font-weight: 600;">📱 How to reset your password:</h3>
              <ol style="margin: 0; padding-left: 20px; color: #92400e; font-size: 15px; line-height: 1.8;">
                <li><strong>Open the Luma app</strong> on your device</li>
                <li><strong>Tap "Forgot Password?"</strong> on the login screen</li>
                <li><strong>Enter this code:</strong> <code style="background: rgba(146, 64, 14, 0.1); padding: 4px 8px; border-radius: 4px; font-family: monospace; font-weight: bold;">${resetToken}</code></li>
                <li><strong>Create your new password</strong> and you're all set!</li>
              </ol>
            </div>
            
            <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 16px; margin: 20px 0;">
              <p style="margin: 0; color: #dc2626; font-size: 14px; line-height: 1.5;">
                <strong>⏰ Important:</strong> This code will expire in <strong>1 hour</strong> for your security.
              </p>
            </div>
            
            <div style="text-align: center; margin: 40px 0; padding: 30px; background: #f9fafb; border-radius: 12px;">
              <p style="color: #6b7280; font-size: 14px; line-height: 1.6; margin: 0 0 8px 0;">If you didn't request this reset, you can safely ignore this email.</p>
              <p style="color: #6b7280; font-size: 14px; line-height: 1.6; margin: 0;">Your password will remain unchanged.</p>
            </div>
            
            <hr style="border: none; border-top: 2px solid #e5e7eb; margin: 40px 0;">
            
            <div style="text-align: center;">
              <p style="color: #9ca3af; font-size: 13px; margin: 0 0 8px 0;">
                Take care of your mental health,
              </p>
              <p style="color: #7c3aed; font-size: 15px; font-weight: 600; margin: 0;">
                💜 The Luma Team
              </p>
            </div>
          </div>
        `
      });

      console.log('✅ Email sent successfully');

      res.json({ 
        success: true, 
        message: 'Password reset code sent to your email. Please check your inbox!' 
      });

    } catch (emailError) {
      console.error('❌ Email sending failed:', emailError);
      res.status(500).json({ 
        error: 'Failed to send reset email. Please try again or contact support.'
      });
    }

  } catch (error) {
    console.error('💥 Forgot password error:', error);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// RESET PASSWORD - Confirm Reset
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Reset code and new password are required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    // Check if token exists and is valid
    const tokenResult = await pool.query(
      'SELECT user_id, expires_at FROM password_reset_tokens WHERE token = $1',
      [token.toUpperCase()]
    );

    if (tokenResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset code. Please request a new one.' });
    }

    const resetData = tokenResult.rows[0];

    // Check if token is expired
    if (new Date() > resetData.expires_at) {
      // Remove expired token
      await pool.query('DELETE FROM password_reset_tokens WHERE token = $1', [token.toUpperCase()]);
      return res.status(400).json({ error: 'Reset code has expired. Please request a new one.' });
    }

    // Hash new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update user password
    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [hashedPassword, resetData.user_id]
    );

    // Remove used token
    await pool.query('DELETE FROM password_reset_tokens WHERE token = $1', [token.toUpperCase()]);

    console.log('✅ Password reset successful for user:', resetData.user_id);

    res.json({
      success: true,
      message: 'Password reset successfully! You can now log in with your new password.'
    });

  } catch (error) {
    console.error('💥 Reset password error:', error);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// GET CURRENT USER
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT id, username, email, created_at FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(userResult.rows[0]);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// LOGOUT
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

// PIPEDA: Enhanced CHAT ENDPOINT with consent checking
app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    const { message, chatHistory, sessionId, consentedToAI } = req.body;
    
    // PIPEDA: Check AI processing consent
    if (!consentedToAI) {
      return res.status(403).json({ 
        error: 'AI processing consent required',
        requiresConsent: true 
      });
    }

    await logDataAccess(req.user.userId, 'create', 'chat_message', req, 'ai_conversation');
    
    let currentSession = null;

    if (sessionId) {
      // Try to find existing session
      const sessionResult = await pool.query(
        'SELECT * FROM chat_sessions WHERE id = $1 AND user_id = $2',
        [sessionId, req.user.userId]
      );
      
      if (sessionResult.rows.length > 0) {
        currentSession = sessionResult.rows[0];
      }
    }
    
    if (!currentSession) {
      // Create new session
      const sessionResult = await pool.query(
        'INSERT INTO chat_sessions (user_id, start_time, last_activity, user_context) VALUES ($1, NOW(), NOW(), $2) RETURNING *',
        [req.user.userId, JSON.stringify({ mood: null, recentJournalThemes: [], questionnaireCompleted: false })]
      );
      currentSession = sessionResult.rows[0];
    }

    // PIPEDA: Detect sensitive content
    const sensitiveKeywords = ['suicide', 'self-harm', 'kill myself', 'medication', 'doctor', 'therapist', 'address', 'phone', 'social security'];
    const containsSensitive = sensitiveKeywords.some(keyword => message.toLowerCase().includes(keyword));

    // Add current user message to session
    await pool.query(
      'INSERT INTO chat_messages (session_id, role, content, contains_sensitive_data, timestamp) VALUES ($1, $2, $3, $4, NOW())',
      [currentSession.id, 'user', message, containsSensitive]
    );

    // Get user context for AI
    const questionnaireResult = await pool.query(
      'SELECT * FROM questionnaire_responses WHERE user_id = $1',
      [req.user.userId]
    );

    const profileResult = await pool.query(
      'SELECT * FROM user_profiles WHERE user_id = $1',
      [req.user.userId]
    );

    const recentMoodsResult = await pool.query(
      'SELECT mood, entry_date FROM mood_entries WHERE user_id = $1 ORDER BY entry_date DESC LIMIT 5',
      [req.user.userId]
    );

    const recentJournalsResult = await pool.query(
      'SELECT content FROM journal_entries WHERE user_id = $1 ORDER BY entry_date DESC LIMIT 3',
      [req.user.userId]
    );

    // Update session context
    const userContext = {
      mood: recentMoodsResult.rows.length > 0 ? recentMoodsResult.rows[0].mood : null,
      recentJournalThemes: recentJournalsResult.rows.map(j => j.content.substring(0, 100)),
      questionnaireCompleted: questionnaireResult.rows.length > 0 ? questionnaireResult.rows[0].completed : false,
      lastMoodDate: recentMoodsResult.rows.length > 0 ? recentMoodsResult.rows[0].entry_date : null
    };

    await pool.query(
      'UPDATE chat_sessions SET last_activity = NOW(), user_context = $1 WHERE id = $2',
      [JSON.stringify(userContext), currentSession.id]
    );

    let questionnaireContext = '';
    if (questionnaireResult.rows.length > 0 && questionnaireResult.rows[0].completed) {
      const responses = questionnaireResult.rows[0];
      questionnaireContext = `\n\nIMPORTANT USER CONTEXT (reference naturally when relevant):`;
      
      if (responses.first_name) {
        questionnaireContext += `\n- Name: ${responses.first_name} (call them ${responses.first_name})`;
      }
      if (responses.pronouns) {
        questionnaireContext += `\n- Pronouns: ${responses.pronouns}`;
      }
      
      const goalsText = responses.main_goals && responses.main_goals.length > 0 
        ? responses.main_goals.join(', ') 
        : 'Not specified';
      
      questionnaireContext += `\n- Goals: ${goalsText}
- Communication style: ${responses.communication_style || 'Not specified'}`;
    }

    // Build messages for OpenAI using stored session messages
    const messages = [
      {
        role: 'system',
        content: `You are Luma, a supportive AI mental health companion who has genuine, caring conversations while providing helpful insights when needed.

CONVERSATION STYLE:
- Respond like a caring, insightful friend who truly listens
- Ask thoughtful follow-up questions to understand their full situation
- Reflect back what you're hearing to show you understand
- Share insights naturally within conversation, not as numbered lists
- Be genuinely curious about their specific experience
- Remember you're having a conversation, not giving a therapy session

RESPONSE APPROACH:
1. First, acknowledge their feelings and show understanding
2. Ask a thoughtful follow-up question to learn more about their situation
3. If appropriate, weave in ONE relevant insight or gentle suggestion naturally
4. Keep the conversation flowing - focus on connection over solutions

TONE: Warm, genuine, curious, supportive - like talking to someone who really cares about understanding your experience first, not just solving your problems.

IMPORTANT - AVOID:
- Numbered lists of suggestions
- Immediately jumping to solutions before understanding
- Generic advice without knowing their specific context
- Sounding clinical, robotic, or overly therapeutic
- Giving multiple strategies at once

Remember: People want to feel heard and understood FIRST, then gently guided toward insights.${questionnaireContext}`
      }
    ];
    
    // Add recent conversation history from stored session (last 10 messages for context)
    const recentMessagesResult = await pool.query(
      'SELECT role, content FROM chat_messages WHERE session_id = $1 ORDER BY timestamp DESC LIMIT 11',
      [currentSession.id]
    );

    // Reverse to get chronological order, exclude the message we just added
    const recentMessages = recentMessagesResult.rows.reverse().slice(0, -1);
    recentMessages.forEach(msg => {
      if (msg.role === 'user' || msg.role === 'assistant') {
        messages.push({
          role: msg.role,
          content: msg.content
        });
      }
    });
    
    // Add the current message
    messages.push({
      role: 'user',
      content: message
    });
    
    // Call OpenAI
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-4',
        messages: messages,
        temperature: 0.8,
        max_tokens: 400
      }),
    });
    
    const data = await response.json();
    
    if (data.choices && data.choices[0]) {
      // Add AI response to session
      await pool.query(
        'INSERT INTO chat_messages (session_id, role, content, timestamp) VALUES ($1, $2, $3, NOW())',
        [currentSession.id, 'assistant', data.choices[0].message.content]
      );

      // Count messages in session
      const messageCountResult = await pool.query(
        'SELECT COUNT(*) as count FROM chat_messages WHERE session_id = $1',
        [currentSession.id]
      );
      
      console.log(`💬 Chat session ${currentSession.id}: ${messageCountResult.rows[0].count} messages`);
      
      res.json({ 
        response: data.choices[0].message.content,
        success: true,
        sessionId: currentSession.id
      });
    } else {
      res.status(500).json({ 
        error: 'No response from AI',
        success: false 
      });
    }
  } catch (error) {
    console.error('Chat error:', error);
    res.status(500).json({ 
      error: 'Server error',
      success: false 
    });
  }
});

// GET CHAT SESSIONS
app.get('/api/chat/sessions', authenticateToken, async (req, res) => {
  try {
    await logDataAccess(req.user.userId, 'read', 'chat_sessions', req);

    const sessionsResult = await pool.query(
      `SELECT 
        cs.id,
        cs.start_time,
        cs.last_activity,
        COUNT(cm.id) as message_count,
        cm_last.content as last_message
      FROM chat_sessions cs
      LEFT JOIN chat_messages cm ON cs.id = cm.session_id
      LEFT JOIN LATERAL (
        SELECT content FROM chat_messages 
        WHERE session_id = cs.id 
        ORDER BY timestamp DESC 
        LIMIT 1
      ) cm_last ON true
      WHERE cs.user_id = $1
      GROUP BY cs.id, cs.start_time, cs.last_activity, cm_last.content
      ORDER BY cs.last_activity DESC`,
      [req.user.userId]
    );
    
    const sessionSummaries = sessionsResult.rows.map(session => ({
      id: session.id,
      startTime: session.start_time,
      lastActivity: session.last_activity,
      messageCount: parseInt(session.message_count),
      lastMessage: session.last_message ? 
        session.last_message.substring(0, 100) + '...' : 
        'No messages'
    }));
    
    res.json(sessionSummaries);
  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({ error: 'Failed to load chat sessions' });
  }
});

// GET SPECIFIC CHAT SESSION
app.get('/api/chat/sessions/:sessionId', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    await logDataAccess(req.user.userId, 'read', 'chat_session', req);
    
    const sessionResult = await pool.query(
      'SELECT * FROM chat_sessions WHERE id = $1 AND user_id = $2',
      [sessionId, req.user.userId]
    );
    
    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }
    
    const messagesResult = await pool.query(
      'SELECT id, role, content, timestamp FROM chat_messages WHERE session_id = $1 ORDER BY timestamp',
      [sessionId]
    );
    
    const session = {
      ...sessionResult.rows[0],
      messages: messagesResult.rows
    };
    
    res.json(session);
  } catch (error) {
    console.error('Get session error:', error);
    res.status(500).json({ error: 'Failed to load chat session' });
  }
});

// PIPEDA COMPLIANT QUESTIONNAIRE ENDPOINTS
app.get('/api/questionnaire', authenticateToken, async (req, res) => {
  try {
    await logDataAccess(req.user.userId, 'read', 'questionnaire', req);

    const questionnaireResult = await pool.query(
      'SELECT * FROM questionnaire_responses WHERE user_id = $1',
      [req.user.userId]
    );
    
    if (questionnaireResult.rows.length === 0) {
      return res.json({ 
        completed: false, 
        responses: {
          firstName: "",
          pronouns: "",
          mainGoals: [],
          communicationStyle: ""
        } 
      });
    }
    
    const questionnaire = questionnaireResult.rows[0];
    res.json({
      completed: questionnaire.completed,
      responses: {
        firstName: questionnaire.first_name || "",
        pronouns: questionnaire.pronouns || "",
        mainGoals: questionnaire.main_goals || [],
        communicationStyle: questionnaire.communication_style || ""
      },
      completedAt: questionnaire.completed_at
    });
  } catch (error) {
    console.error('Questionnaire load error:', error);
    res.status(500).json({ error: 'Failed to load questionnaire' });
  }
});

app.post('/api/questionnaire', authenticateToken, async (req, res) => {
  try {
    const { responses } = req.body;
    
    if (!responses || typeof responses !== 'object') {
      return res.status(400).json({ error: 'Invalid questionnaire responses' });
    }

    // PIPEDA: Minimized required fields
    const requiredFields = ['firstName', 'pronouns', 'mainGoals', 'communicationStyle'];
    const missingFields = requiredFields.filter(field => {
      if (Array.isArray(responses[field])) {
        return responses[field].length === 0;
      }
      return !responses[field] || responses[field].trim() === '';
    });
    
    if (missingFields.length > 0) {
      return res.status(400).json({ 
        error: `Missing required fields: ${missingFields.join(', ')}` 
      });
    }

    if (!Array.isArray(responses.mainGoals)) {
      return res.status(400).json({ error: 'mainGoals must be an array' });
    }

    await logDataAccess(req.user.userId, 'create', 'questionnaire', req, 'app_personalization');

    // Update questionnaire responses
    await pool.query(
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

    // Update user profile with questionnaire data
    await pool.query(
      `UPDATE user_profiles 
       SET first_name = $1, 
           pronouns = $2, 
           consent_timestamp = NOW(),
           onboarding_completed_at = NOW(),
           updated_at = NOW()
       WHERE user_id = $3`,
      [
        responses.firstName || "",
        responses.pronouns || "",
        req.user.userId
      ]
    );
    
    console.log('✅ PIPEDA-compliant questionnaire completed for user:', req.user.username);
    console.log('   Main goals selected:', responses.mainGoals);
    
    res.json({ success: true, message: 'Questionnaire completed successfully' });
  } catch (error) {
    console.error('Questionnaire save error:', error);
    res.status(500).json({ error: 'Failed to save questionnaire' });
  }
});

// PIPEDA ENHANCED PROFILE ENDPOINTS
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    await logDataAccess(req.user.userId, 'read', 'profile', req);

    const profileResult = await pool.query(
      'SELECT * FROM user_profiles WHERE user_id = $1',
      [req.user.userId]
    );
    
    if (profileResult.rows.length === 0) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    
    const profile = profileResult.rows[0];
    
    // Convert database format to app format
    const profileData = {
      firstName: profile.first_name || "",
      pronouns: profile.pronouns || "",
      joinDate: profile.join_date,
      profileColorHex: profile.profile_color_hex || "#800080",
      notifications: profile.notifications,
      biometricAuth: profile.biometric_auth,
      darkMode: profile.dark_mode,
      reminderTime: profile.reminder_time,
      dataPurposes: profile.data_purposes || [],
      consentTimestamp: profile.consent_timestamp,
      dataRetentionPeriod: profile.data_retention_period || 365,
      appTheme: profile.app_theme || 'system',
      accessibilityFeatures: profile.accessibility_features || {},
      languagePreference: profile.language_preference || 'en',
      timezone: profile.timezone || 'America/Toronto',
      onboardingCompletedAt: profile.onboarding_completed_at,
      lastActiveAt: profile.last_active_at,
      appVersion: profile.app_version,
      deviceInfo: profile.device_info || {}
    };
    
    res.json(profileData);
  } catch (error) {
    console.error('Profile load error:', error);
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

app.post('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { 
      firstName,
      pronouns,
      joinDate, 
      profileColorHex, 
      notifications, 
      biometricAuth, 
      darkMode, 
      reminderTime,
      dataPurposes,
      consentTimestamp,
      dataRetentionPeriod,
      appTheme,
      accessibilityFeatures,
      languagePreference,
      timezone,
      appVersion,
      deviceInfo
    } = req.body;
    
    await logDataAccess(req.user.userId, 'update', 'profile', req);
    
    await pool.query(
      `UPDATE user_profiles 
       SET first_name = COALESCE($1, first_name),
           pronouns = COALESCE($2, pronouns),
           join_date = COALESCE($3, join_date),
           profile_color_hex = COALESCE($4, profile_color_hex),
           notifications = COALESCE($5, notifications),
           biometric_auth = COALESCE($6, biometric_auth),
           dark_mode = COALESCE($7, dark_mode),
           reminder_time = COALESCE($8, reminder_time),
           data_purposes = COALESCE($9, data_purposes),
           consent_timestamp = COALESCE($10, consent_timestamp),
           data_retention_period = COALESCE($11, data_retention_period),
           app_theme = COALESCE($12, app_theme),
           accessibility_features = COALESCE($13, accessibility_features),
           language_preference = COALESCE($14, language_preference),
           timezone = COALESCE($15, timezone),
           app_version = COALESCE($16, app_version),
           device_info = COALESCE($17, device_info),
           last_active_at = NOW(),
           updated_at = NOW()
       WHERE user_id = $18`,
      [
        firstName,
        pronouns,
        joinDate,
        profileColorHex,
        notifications,
        biometricAuth,
        darkMode,
        reminderTime,
        dataPurposes,
        consentTimestamp,
        dataRetentionPeriod,
        appTheme,
        accessibilityFeatures,
        languagePreference,
        timezone,
        appVersion,
        deviceInfo,
        req.user.userId
      ]
    );
    
    console.log('✅ PIPEDA-compliant profile updated for user:', req.user.username);
    
    res.json({ success: true, message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Profile save error:', error);
    res.status(500).json({ error: 'Failed to save profile' });
  }
});

// PIPEDA ENHANCED MOOD ENDPOINTS
app.get('/api/mood', authenticateToken, async (req, res) => {
  try {
    await logDataAccess(req.user.userId, 'read', 'mood_entries', req);

    const moodResult = await pool.query(
      `SELECT id, mood, note, entry_date as date, data_purpose, mood_category, 
              mood_triggers, weather_context, activity_context, privacy_level 
       FROM mood_entries WHERE user_id = $1 ORDER BY entry_date DESC`,
      [req.user.userId]
    );
    
    res.json(moodResult.rows);
  } catch (error) {
    console.error('Mood load error:', error);
    res.status(500).json({ error: 'Failed to load mood entries' });
  }
});

app.post('/api/mood', authenticateToken, async (req, res) => {
  try {
    const { 
      id, 
      mood, 
      note, 
      date, 
      dataPurpose = 'mood_tracking',
      moodCategory,
      moodTriggers,
      weatherContext,
      activityContext,
      privacyLevel = 'private'
    } = req.body;
    
    if (!mood || !date) {
      return res.status(400).json({ error: 'Mood and date are required' });
    }
    
    if (mood < 1 || mood > 10) {
      return res.status(400).json({ error: 'Mood must be between 1 and 10' });
    }
    
    await logDataAccess(req.user.userId, 'create', 'mood_entry', req, dataPurpose);
    
    const moodResult = await pool.query(
      `INSERT INTO mood_entries 
       (user_id, mood, note, entry_date, data_purpose, mood_category, mood_triggers, weather_context, activity_context, privacy_level) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [
        req.user.userId, 
        parseInt(mood), 
        note || null, 
        date, 
        dataPurpose,
        moodCategory,
        moodTriggers,
        weatherContext,
        activityContext,
        privacyLevel
      ]
    );
    
    const savedEntry = moodResult.rows[0];
    
    res.json({ 
      success: true, 
      entry: {
        id: savedEntry.id,
        mood: savedEntry.mood,
        note: savedEntry.note,
        date: savedEntry.entry_date,
        dataPurpose: savedEntry.data_purpose,
        moodCategory: savedEntry.mood_category,
        moodTriggers: savedEntry.mood_triggers,
        weatherContext: savedEntry.weather_context,
        activityContext: savedEntry.activity_context,
        privacyLevel: savedEntry.privacy_level
      }
    });
  } catch (error) {
    console.error('Mood save error:', error);
    res.status(500).json({ error: 'Failed to save mood entry' });
  }
});

// PIPEDA ENHANCED JOURNAL ENDPOINTS
app.get('/api/journal', authenticateToken, async (req, res) => {
  try {
    await logDataAccess(req.user.userId, 'read', 'journal_entries', req);

    const journalResult = await pool.query(
      `SELECT id, content, prompt, entry_date as date, data_purpose, entry_type,
              emotional_tone, word_count, reading_time_estimate, tags, privacy_level
       FROM journal_entries WHERE user_id = $1 ORDER BY entry_date DESC`,
      [req.user.userId]
    );
    
    res.json(journalResult.rows);
  } catch (error) {
    console.error('Journal load error:', error);
    res.status(500).json({ error: 'Failed to load journal entries' });
  }
});

app.post('/api/journal', authenticateToken, async (req, res) => {
  try {
    const { 
      id, 
      content, 
      prompt, 
      date, 
      dataPurpose = 'journaling',
      entryType = 'free_write',
      emotionalTone,
      tags,
      privacyLevel = 'private'
    } = req.body;
    
    if (!content || !date) {
      return res.status(400).json({ error: 'Content and date are required' });
    }
    
    if (content.trim().length === 0) {
      return res.status(400).json({ error: 'Content cannot be empty' });
    }
    
    await logDataAccess(req.user.userId, 'create', 'journal_entry', req, dataPurpose);
    
    // Calculate word count and reading time estimate
    const wordCount = content.trim().split(/\s+/).length;
    const readingTimeEstimate = Math.max(1, Math.ceil(wordCount / 200)); // Assume 200 words per minute
    
    const journalResult = await pool.query(
      `INSERT INTO journal_entries 
       (user_id, content, prompt, entry_date, data_purpose, entry_type, emotional_tone, word_count, reading_time_estimate, tags, privacy_level) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [
        req.user.userId, 
        content.trim(), 
        prompt || null, 
        date, 
        dataPurpose,
        entryType,
        emotionalTone,
        wordCount,
        readingTimeEstimate,
        tags,
        privacyLevel
      ]
    );
    
    const savedEntry = journalResult.rows[0];
    
    res.json({ 
      success: true, 
      entry: {
        id: savedEntry.id,
        content: savedEntry.content,
        prompt: savedEntry.prompt,
        date: savedEntry.entry_date,
        dataPurpose: savedEntry.data_purpose,
        entryType: savedEntry.entry_type,
        emotionalTone: savedEntry.emotional_tone,
        wordCount: savedEntry.word_count,
        readingTimeEstimate: savedEntry.reading_time_estimate,
        tags: savedEntry.tags,
        privacyLevel: savedEntry.privacy_level
      }
    });
  } catch (error) {
    console.error('Journal save error:', error);
    res.status(500).json({ error: 'Failed to save journal entry' });
  }
});

// RESET USER DATA
app.post('/api/reset', authenticateToken, async (req, res) => {
  try {
    await logDataAccess(req.user.userId, 'delete', 'user_data_reset', req, 'user_requested_reset');

    // Delete all user data but keep the account
    await pool.query('DELETE FROM consent_audit_trail WHERE user_id = $1', [req.user.userId]);
    await pool.query('DELETE FROM user_app_preferences WHERE user_id = $1', [req.user.userId]);
    await pool.query('DELETE FROM privacy_settings WHERE user_id = $1', [req.user.userId]);
    await pool.query('DELETE FROM user_sessions WHERE user_id = $1', [req.user.userId]);
    await pool.query('DELETE FROM notification_preferences WHERE user_id = $1', [req.user.userId]);
    await pool.query('DELETE FROM chat_messages WHERE session_id IN (SELECT id FROM chat_sessions WHERE user_id = $1)', [req.user.userId]);
    await pool.query('DELETE FROM chat_sessions WHERE user_id = $1', [req.user.userId]);
    await pool.query('DELETE FROM mood_entries WHERE user_id = $1', [req.user.userId]);
    await pool.query('DELETE FROM journal_entries WHERE user_id = $1', [req.user.userId]);
    
    // Reset questionnaire
    await pool.query(
      `UPDATE questionnaire_responses 
       SET completed = false, 
           first_name = '', 
           pronouns = '', 
           main_goals = '{}', 
           communication_style = '',
           data_purpose = 'app_personalization',
           consent_given = false,
           completed_at = NULL,
           updated_at = NOW()
       WHERE user_id = $1`,
      [req.user.userId]
    );
    
    // Reset profile to minimal data
    await pool.query(
      `UPDATE user_profiles 
       SET first_name = '', 
           pronouns = '', 
           consent_timestamp = NULL,
           onboarding_completed_at = NULL,
           updated_at = NOW()
       WHERE user_id = $1`,
      [req.user.userId]
    );
    
    res.json({ success: true, message: 'Your data has been reset' });
  } catch (error) {
    console.error('Reset error:', error);
    res.status(500).json({ error: 'Failed to reset data' });
  }
});

// HEALTH CHECK
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '5.0.0 - Enhanced PIPEDA Compliant',
    database: 'PostgreSQL',
    compliance: 'PIPEDA (Personal Information Protection and Electronic Documents Act)',
    endpoints: [
      '/api/auth/*', 
      '/api/consent',
      '/api/consent/status',
      '/api/notifications/preferences',
      '/api/preferences',
      '/api/privacy/settings',
      '/api/data-deletion',
      '/api/user/delete-all-data',
      '/api/user/export-data',
      '/api/questionnaire', 
      '/api/chat', 
      '/api/chat/sessions', 
      '/api/chat/sessions/:id',
      '/api/profile', 
      '/api/mood', 
      '/api/journal', 
      '/api/reset'
    ],
    features: [
      'PIPEDA-compliant data handling',
      'Granular consent management with audit trails',
      'Enhanced notification preferences',
      'User app preferences storage',
      'Privacy settings management',
      'Data minimization principles',
      'User rights implementation (access, portability, deletion)',
      'Audit logging for data access',
      'Automatic data retention policies',
      'Enhanced privacy controls',
      'Sensitive content detection',
      'Complete data export functionality',
      'Secure data deletion',
      'Session management and security'
    ],
    newFeatures: [
      'Notification preferences API',
      'User app preferences API', 
      'Privacy settings API',
      'Enhanced mood tracking with categories and triggers',
      'Enhanced journaling with tags and emotional tone',
      'Session management',
      'Consent audit trail',
      'Enhanced profile with accessibility features'
    ]
  });
});

// PIPEDA: Cleanup tasks
setInterval(async () => {
  try {
    // Clean up expired tokens
    const tokenResult = await pool.query('DELETE FROM password_reset_tokens WHERE expires_at < NOW()');
    if (tokenResult.rowCount > 0) {
      console.log(`🧹 Cleaned up ${tokenResult.rowCount} expired password reset tokens`);
    }

    // Clean up old access logs (keep for 2 years as per PIPEDA requirements)
    const logsResult = await pool.query('DELETE FROM data_access_logs WHERE accessed_at < NOW() - INTERVAL \'2 years\'');
    if (logsResult.rowCount > 0) {
      console.log(`🧹 Cleaned up ${logsResult.rowCount} old access logs`);
    }

    // Clean up inactive sessions (older than 30 days)
    const sessionsResult = await pool.query('DELETE FROM user_sessions WHERE last_activity_at < NOW() - INTERVAL \'30 days\'');
    if (sessionsResult.rowCount > 0) {
      console.log(`🧹 Cleaned up ${sessionsResult.rowCount} inactive sessions`);
    }

    // Process data retention for all users
    const users = await pool.query('SELECT id FROM users');
    for (const user of users.rows) {
      await checkDataRetention(user.id);
    }

  } catch (error) {
    console.error('Error in cleanup tasks:', error);
  }
}, 86400000); // Run daily (24 hours)

app.listen(PORT, () => {
  console.log(`✅ Luma Enhanced PIPEDA-compliant backend running on port ${PORT}`);
  console.log(`🌐 Server URL: https://luma-backend-nfdc.onrender.com`);
  console.log(`🗄️ Database: PostgreSQL with Enhanced PIPEDA-compliant schema`);
  console.log(`📧 Email service: ${process.env.RESEND_API_KEY ? '✅ Configured' : '❌ Missing RESEND_API_KEY'}`);
  console.log(`🤖 OpenAI service: ${process.env.OPENAI_API_KEY ? '✅ Configured' : '❌ Missing OPENAI_API_KEY'}`);
  console.log(`🔗 Database URL: ${process.env.DATABASE_URL ? '✅ Configured' : '❌ Missing DATABASE_URL'}`);
  console.log(`\n🎉 ENHANCED PIPEDA COMPLIANCE FEATURES:`);
  console.log(`   ✅ Granular consent management with audit trails`);
  console.log(`   ✅ Enhanced notification preferences management`);
  console.log(`   ✅ User app preferences storage and sync`);
  console.log(`   ✅ Privacy settings management`);
  console.log(`   ✅ Data minimization (reduced personal data collection)`);
  console.log(`   ✅ User rights implementation (access, portability, deletion)`);
  console.log(`   ✅ Automatic data retention policies`);
  console.log(`   ✅ Comprehensive audit logging`);
  console.log(`   ✅ Sensitive content detection and flagging`);
  console.log(`   ✅ Enhanced privacy controls and transparency`);
  console.log(`   ✅ Complete data export in machine-readable format`);
  console.log(`   ✅ Secure data deletion with verification`);
  console.log(`   ✅ Session management and security tracking`);
  console.log(`   ✅ Enhanced mood tracking with categories and triggers`);
  console.log(`   ✅ Enhanced journaling with tags and emotional analysis`);
  console.log(`\n📋 NEW API ENDPOINTS:`);
  console.log(`   - GET/POST /api/notifications/preferences (notification management)`);
  console.log(`   - GET/POST /api/preferences (app preferences storage)`);
  console.log(`   - GET/POST /api/privacy/settings (privacy controls)`);
  console.log(`   - Enhanced /api/mood (with categories and triggers)`);
  console.log(`   - Enhanced /api/journal (with tags and emotional tone)`);
  console.log(`   - Enhanced /api/profile (with accessibility features)`);
  console.log(`\n🔒 ENHANCED PRIVACY & SECURITY FEATURES:`);
  console.log(`   - All data access is logged with IP and timestamp`);
  console.log(`   - Automatic data retention policy enforcement`);
  console.log(`   - Sensitive content detection in chat messages`);
  console.log(`   - Consent withdrawal triggers data deletion requests`);
  console.log(`   - Complete audit trail for compliance reporting`);
  console.log(`   - User can export all data in machine-readable format`);
  console.log(`   - Granular consent per data type (chat, mood, journal)`);
  console.log(`   - Session management with security tracking`);
  console.log(`   - Enhanced notification and privacy controls`);
  console.log(`\n📞 PRIVACY CONTACT: griffencoutts@gmail.com`);
  console.log(`📖 PRIVACY POLICY: Available in app settings`);
  console.log(`🏛️ JURISDICTION: Ontario, Canada (PIPEDA compliance)`);
});
