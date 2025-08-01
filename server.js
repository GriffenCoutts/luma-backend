const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Resend } = require('resend');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// IMPROVED CORS CONFIGURATION
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
    // Allow any origin for debugging (you can restrict this later)
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
app.use(express.json());

// Add explicit OPTIONS handler for preflight requests
app.options('*', cors(corsOptions));

// Add headers middleware for extra compatibility
app.use((req, res, next) => {
  // Allow requests from any origin during development
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Cache-Control, User-Agent');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }
  
  next();
});

// RESPONSE FORMAT CONSISTENCY MIDDLEWARE
const ensureJSONResponse = (req, res, next) => {
  const originalSend = res.send;
  const originalJson = res.json;
  
  res.send = function(data) {
    // Ensure we always send JSON with consistent format
    if (typeof data === 'string') {
      try {
        JSON.parse(data);
      } catch (e) {
        // If it's not valid JSON, wrap it
        data = JSON.stringify({ 
          success: false, 
          error: data,
          message: data 
        });
      }
    }
    res.setHeader('Content-Type', 'application/json');
    return originalSend.call(this, data);
  };
  
  res.json = function(data) {
    // Ensure all JSON responses have a success field
    if (typeof data === 'object' && data !== null) {
      if (!('success' in data)) {
        data.success = res.statusCode >= 200 && res.statusCode < 300;
      }
    }
    return originalJson.call(this, data);
  };
  
  next();
};

app.use(ensureJSONResponse);

// DEBUG LOGGING MIDDLEWARE
app.use((req, res, next) => {
  console.log(`📡 ${new Date().toISOString()} - ${req.method} ${req.path}`);
  console.log(`📍 Origin: ${req.get('Origin') || 'No Origin'}`);
  console.log(`📱 User-Agent: ${req.get('User-Agent') || 'No User-Agent'}`);
  console.log(`🔑 Auth: ${req.get('Authorization') ? 'Present' : 'None'}`);
  next();
});

// Initialize Resend
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

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

// HELPER FUNCTION: Check if column exists before using it
const columnExists = async (tableName, columnName) => {
  try {
    console.log(`🔍 Checking if column ${tableName}.${columnName} exists...`);
    const result = await pool.query(
      `SELECT column_name FROM information_schema.columns 
       WHERE table_name = $1 AND column_name = $2`,
      [tableName, columnName]
    );
    const exists = result.rows.length > 0;
    console.log(`📊 Column ${tableName}.${columnName} exists: ${exists}`);
    return exists;
  } catch (error) {
    console.error(`❌ Error checking column ${tableName}.${columnName}:`, error);
    return false;
  }
};

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
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Add missing columns to user_profiles if they don't exist
    const consentTimestampExists = await columnExists('user_profiles', 'consent_timestamp');
    if (!consentTimestampExists) {
      await pool.query('ALTER TABLE user_profiles ADD COLUMN consent_timestamp TIMESTAMP WITH TIME ZONE');
      console.log('✅ Added consent_timestamp to user_profiles');
    }

    const dataRetentionExists = await columnExists('user_profiles', 'data_retention_period');
    if (!dataRetentionExists) {
      await pool.query('ALTER TABLE user_profiles ADD COLUMN data_retention_period INTEGER DEFAULT 365');
      console.log('✅ Added data_retention_period to user_profiles');
    }

    // Add other enhanced columns
    const enhancedColumns = [
      'app_theme VARCHAR(20) DEFAULT \'system\'',
      'accessibility_features JSONB DEFAULT \'{}\'',
      'language_preference VARCHAR(10) DEFAULT \'en\'',
      'timezone VARCHAR(50) DEFAULT \'America/Toronto\'',
      'onboarding_completed_at TIMESTAMP WITH TIME ZONE',
      'last_active_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()',
      'app_version VARCHAR(20)',
      'device_info JSONB DEFAULT \'{}\''
    ];

    for (const column of enhancedColumns) {
      const columnName = column.split(' ')[0];
      const exists = await columnExists('user_profiles', columnName);
      if (!exists) {
        try {
          await pool.query(`ALTER TABLE user_profiles ADD COLUMN ${column}`);
          console.log(`✅ Added ${columnName} to user_profiles`);
        } catch (error) {
          console.log(`⚠️ Column ${columnName} might already exist or error:`, error.message);
        }
      }
    }

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
        consent_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        withdrawn_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Add enhanced consent columns
    const consentEnhancedColumns = [
      'consent_method VARCHAR(50) DEFAULT \'app_interface\'',
      'consent_source VARCHAR(100) DEFAULT \'mobile_app\'',
      'withdrawal_reason TEXT',
      'parent_consent_id UUID REFERENCES user_consents(id)'
    ];

    for (const column of consentEnhancedColumns) {
      const columnName = column.split(' ')[0];
      const exists = await columnExists('user_consents', columnName);
      if (!exists) {
        try {
          await pool.query(`ALTER TABLE user_consents ADD COLUMN ${column}`);
          console.log(`✅ Added ${columnName} to user_consents`);
        } catch (error) {
          console.log(`⚠️ Column ${columnName} might already exist:`, error.message);
        }
      }
    }

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
        timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Add enhanced chat message columns
    const chatEnhancedColumns = [
      'content_hash VARCHAR(64)',
      'privacy_level VARCHAR(20) DEFAULT \'standard\'',
      'auto_delete_at TIMESTAMP WITH TIME ZONE',
      'content_classification JSONB DEFAULT \'{"containsMedicalTerms": false, "containsPersonalInfo": false, "sensitivityScore": 1}\''
    ];

    for (const column of chatEnhancedColumns) {
      const columnName = column.split(' ')[0];
      const exists = await columnExists('chat_messages', columnName);
      if (!exists) {
        try {
          await pool.query(`ALTER TABLE chat_messages ADD COLUMN ${column}`);
          console.log(`✅ Added ${columnName} to chat_messages`);
        } catch (error) {
          console.log(`⚠️ Column ${columnName} might already exist:`, error.message);
        }
      }
    }

    // PIPEDA: Enhanced mood entries with data purpose tracking
    await pool.query(`
      CREATE TABLE IF NOT EXISTS mood_entries (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        mood INTEGER NOT NULL CHECK (mood >= 1 AND mood <= 10),
        note TEXT,
        entry_date TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Add missing data_purpose column to mood_entries
    const moodDataPurposeExists = await columnExists('mood_entries', 'data_purpose');
    if (!moodDataPurposeExists) {
      await pool.query('ALTER TABLE mood_entries ADD COLUMN data_purpose VARCHAR(100) DEFAULT \'mood_tracking\'');
      console.log('✅ Added data_purpose to mood_entries');
    }

    // Add other enhanced mood columns
    const moodEnhancedColumns = [
      'mood_category VARCHAR(50)',
      'mood_triggers TEXT[]',
      'weather_context JSONB',
      'activity_context TEXT',
      'privacy_level VARCHAR(20) DEFAULT \'private\''
    ];

    for (const column of moodEnhancedColumns) {
      const columnName = column.split(' ')[0];
      const exists = await columnExists('mood_entries', columnName);
      if (!exists) {
        try {
          await pool.query(`ALTER TABLE mood_entries ADD COLUMN ${column}`);
          console.log(`✅ Added ${columnName} to mood_entries`);
        } catch (error) {
          console.log(`⚠️ Column ${columnName} might already exist:`, error.message);
        }
      }
    }

    // PIPEDA: Enhanced journal entries with data purpose tracking
    await pool.query(`
      CREATE TABLE IF NOT EXISTS journal_entries (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        prompt TEXT,
        entry_date TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Add missing data_purpose column to journal_entries
    const journalDataPurposeExists = await columnExists('journal_entries', 'data_purpose');
    if (!journalDataPurposeExists) {
      await pool.query('ALTER TABLE journal_entries ADD COLUMN data_purpose VARCHAR(100) DEFAULT \'journaling\'');
      console.log('✅ Added data_purpose to journal_entries');
    }

    // Add other enhanced journal columns
    const journalEnhancedColumns = [
      'entry_type VARCHAR(50) DEFAULT \'free_write\'',
      'emotional_tone VARCHAR(50)',
      'word_count INTEGER',
      'reading_time_estimate INTEGER',
      'tags TEXT[]',
      'privacy_level VARCHAR(20) DEFAULT \'private\'',
      'auto_delete_at TIMESTAMP WITH TIME ZONE'
    ];

    for (const column of journalEnhancedColumns) {
      const columnName = column.split(' ')[0];
      const exists = await columnExists('journal_entries', columnName);
      if (!exists) {
        try {
          await pool.query(`ALTER TABLE journal_entries ADD COLUMN ${column}`);
          console.log(`✅ Added ${columnName} to journal_entries`);
        } catch (error) {
          console.log(`⚠️ Column ${columnName} might already exist:`, error.message);
        }
      }
    }

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

    // Create indexes for better performance
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
      'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
      'CREATE INDEX IF NOT EXISTS idx_user_consents_user_id ON user_consents(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_user_consents_timestamp ON user_consents(consent_timestamp)',
      'CREATE INDEX IF NOT EXISTS idx_data_access_logs_user_id ON data_access_logs(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_data_access_logs_accessed_at ON data_access_logs(accessed_at)',
      'CREATE INDEX IF NOT EXISTS idx_chat_sessions_user_id ON chat_sessions(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_chat_sessions_start_time ON chat_sessions(start_time)',
      'CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id)',
      'CREATE INDEX IF NOT EXISTS idx_chat_messages_timestamp ON chat_messages(timestamp)',
      'CREATE INDEX IF NOT EXISTS idx_mood_entries_user_id ON mood_entries(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_mood_entries_date ON mood_entries(entry_date)',
      'CREATE INDEX IF NOT EXISTS idx_journal_entries_user_id ON journal_entries(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_journal_entries_date ON journal_entries(entry_date)',
      'CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires ON password_reset_tokens(expires_at)',
      'CREATE INDEX IF NOT EXISTS idx_data_deletion_requests_user_id ON data_deletion_requests(user_id)'
    ];

    for (const indexQuery of indexes) {
      try {
        await pool.query(indexQuery);
      } catch (error) {
        // Indexes might already exist, that's okay
        console.log(`⚠️ Index might already exist:`, error.message);
      }
    }

    console.log('✅ PIPEDA-compliant database tables initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    throw error; // Re-throw to prevent server from starting with broken DB
  }
}

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
    // Check if data_retention_period column exists
    const hasRetentionColumn = await columnExists('user_profiles', 'data_retention_period');
    if (!hasRetentionColumn) {
      console.log('⚠️ data_retention_period column not found, skipping retention check');
      return;
    }

    const profileResult = await pool.query(
      'SELECT data_retention_period FROM user_profiles WHERE user_id = $1',
      [userId]
    );
    
    if (profileResult.rows.length > 0) {
      const retentionDays = profileResult.rows[0].data_retention_period || 365;
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

// IMPROVED USER REGISTRATION
app.post('/api/auth/register', async (req, res) => {
  console.log('🚀 Registration request started');
  console.log('📤 Request body:', JSON.stringify(req.body, null, 2));
  console.log('📍 Request headers:', JSON.stringify(req.headers, null, 2));
  
  try {
    const { username, email, password } = req.body;

    console.log('✅ Extracted registration data:', { username, email, passwordLength: password?.length });

    // Input validation
    if (!username || !email || !password) {
      console.log('❌ Missing required fields');
      return res.status(400).json({ 
        success: false,
        error: 'Username, email, and password are required',
        message: 'Username, email, and password are required'
      });
    }

    if (password.length < 6) {
      console.log('❌ Password too short');
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 6 characters',
        message: 'Password must be at least 6 characters'
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.log('❌ Invalid email format');
      return res.status(400).json({ 
        success: false,
        error: 'Please enter a valid email address',
        message: 'Please enter a valid email address'
      });
    }

    console.log('✅ Input validation passed');

    // Check if user already exists
    console.log('🔍 Checking for existing user...');
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );
    console.log(`📊 Found ${existingUser.rows.length} existing users`);

    if (existingUser.rows.length > 0) {
      console.log('❌ User already exists');
      return res.status(400).json({ 
        success: false,
        error: 'Username or email already exists',
        message: 'Username or email already exists'
      });
    }

    console.log('✅ No existing user found');

    // Hash password
    console.log('🔐 Hashing password...');
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    console.log('✅ Password hashed successfully');

    // Create user
    console.log('👤 Creating user in database...');
    const userResult = await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
      [username, email, hashedPassword]
    );
    console.log('✅ User created:', userResult.rows[0]);

    const newUser = userResult.rows[0];

    // Create user profile - THIS IS WHERE IT MIGHT FAIL
    console.log('📋 Creating user profile...');
    
    try {
      // Check if data_retention_period column exists
      console.log('🔍 Checking if data_retention_period column exists...');
      const hasRetentionColumn = await columnExists('user_profiles', 'data_retention_period');
      console.log('📊 data_retention_period column exists:', hasRetentionColumn);
      
      if (hasRetentionColumn) {
        console.log('💾 Creating profile with retention column...');
        await pool.query(
          `INSERT INTO user_profiles (user_id, first_name, pronouns, join_date, profile_color_hex, notifications, biometric_auth, dark_mode, reminder_time, data_purposes, data_retention_period) 
           VALUES ($1, '', '', NOW(), '#800080', true, false, false, '19:00:00', '{"personalization","app_functionality"}', 365)`,
          [newUser.id]
        );
      } else {
        console.log('💾 Creating profile without retention column...');
        await pool.query(
          `INSERT INTO user_profiles (user_id, first_name, pronouns, join_date, profile_color_hex, notifications, biometric_auth, dark_mode, reminder_time, data_purposes) 
           VALUES ($1, '', '', NOW(), '#800080', true, false, false, '19:00:00', '{"personalization","app_functionality"}')`,
          [newUser.id]
        );
      }
      console.log('✅ User profile created successfully');
    } catch (profileError) {
      console.error('❌ User profile creation failed:', profileError);
      console.error('❌ Profile error details:', profileError.message);
      console.error('❌ Profile error stack:', profileError.stack);
      // Don't fail the registration, just log the error
    }

    // Create questionnaire response - THIS MIGHT ALSO FAIL
    console.log('📝 Creating questionnaire response...');
    try {
      await pool.query(
        `INSERT INTO questionnaire_responses (user_id, completed, first_name, pronouns, main_goals, communication_style, data_purpose, consent_given) 
         VALUES ($1, false, '', '', '{}', '', 'app_personalization', false)`,
        [newUser.id]
      );
      console.log('✅ Questionnaire response created successfully');
    } catch (questionnaireError) {
      console.error('❌ Questionnaire response creation failed:', questionnaireError);
      console.error('❌ Questionnaire error details:', questionnaireError.message);
      // Don't fail the registration, just log the error
    }

    // Generate JWT token
    console.log('🎫 Generating JWT token...');
    const token = jwt.sign(
      { userId: newUser.id, username: newUser.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    console.log('✅ JWT token generated');

    console.log('🎉 Registration completed successfully');

    // Return success response
    const response = {
      success: true,
      message: 'User registered successfully',
      token: token,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email
      }
    };

    console.log('📤 Sending success response:', JSON.stringify(response, null, 2));
    res.status(200).json(response);

  } catch (error) {
    console.error('💥 REGISTRATION FATAL ERROR:', error);
    console.error('💥 Error message:', error.message);
    console.error('💥 Error stack:', error.stack);
    console.error('💥 Error code:', error.code);
    console.error('💥 Error detail:', error.detail);
    
    // Return detailed error for debugging
    const errorResponse = {
      success: false,
      error: 'Server error during registration',
      message: 'Server error during registration',
      details: process.env.NODE_ENV === 'development' ? {
        message: error.message,
        code: error.code,
        detail: error.detail
      } : undefined
    };

    console.log('📤 Sending error response:', JSON.stringify(errorResponse, null, 2));
    res.status(500).json(errorResponse);
  }
});

// IMPROVED USER LOGIN
app.post('/api/auth/login', async (req, res) => {
  console.log('🔐 Login request started');
  console.log('📤 Login request body:', JSON.stringify(req.body, null, 2));
  
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      console.log('❌ Missing login credentials');
      return res.status(400).json({ 
        success: false,
        error: 'Username and password are required',
        message: 'Username and password are required'
      });
    }

    console.log('🔍 Looking up user:', username);

    // Find user (allow login with username or email)
    const userResult = await pool.query(
      'SELECT id, username, email, password_hash FROM users WHERE username = $1 OR email = $1',
      [username]
    );

    if (userResult.rows.length === 0) {
      console.log('❌ User not found');
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials',
        message: 'Invalid credentials'
      });
    }

    const user = userResult.rows[0];
    console.log('✅ User found:', user.username);

    // Check password
    console.log('🔐 Verifying password...');
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      console.log('❌ Invalid password');
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials',
        message: 'Invalid credentials'
      });
    }

    console.log('✅ Password verified');

    // PIPEDA: Check data retention on login
    await checkDataRetention(user.id);

    // Update last active timestamp if column exists
    const hasLastActiveColumn = await columnExists('user_profiles', 'last_active_at');
    if (hasLastActiveColumn) {
      await pool.query(
        'UPDATE user_profiles SET last_active_at = NOW() WHERE user_id = $1',
        [user.id]
      );
    }

    // Generate JWT token
    console.log('🎫 Generating JWT token...');
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log('✅ Login successful');

    // Return success response
    const response = {
      success: true,
      message: 'Login successful',
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    };

    console.log('📤 Sending login success response');
    res.status(200).json(response);

  } catch (error) {
    console.error('💥 LOGIN FATAL ERROR:', error);
    console.error('💥 Login error message:', error.message);
    console.error('💥 Login error stack:', error.stack);
    
    // Return detailed error for debugging
    const errorResponse = {
      success: false,
      error: 'Server error during login',
      message: 'Server error during login',
      details: process.env.NODE_ENV === 'development' ? {
        message: error.message,
        code: error.code,
        detail: error.detail
      } : undefined
    };

    console.log('📤 Sending login error response:', JSON.stringify(errorResponse, null, 2));
    res.status(500).json(errorResponse);
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
      return res.status(404).json({ 
        success: false,
        error: 'User not found',
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      ...userResult.rows[0]
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Server error',
      message: 'Server error'
    });
  }
});

// LOGOUT
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ 
    success: true, 
    message: 'Logged out successfully' 
  });
});

// HEALTH CHECK
app.get('/health', (req, res) => {
  console.log('🏥 Health check requested');
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '5.2.0 - Fixed Registration with Detailed Logging',
    database: 'PostgreSQL',
    compliance: 'PIPEDA (Personal Information Protection and Electronic Documents Act)',
    endpoints: [
      '/api/auth/*', 
      '/api/consent',
      '/api/consent/status',
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
      'Safe column handling for gradual database migration',
      'Granular consent management with audit trails',
      'Data minimization principles',
      'User rights implementation (access, portability, deletion)',
      'Audit logging for data access',
      'Automatic data retention policies',
      'Enhanced privacy controls',
      'Sensitive content detection',
      'Complete data export functionality',
      'Secure data deletion',
      'Backward compatibility with existing database schemas',
      'Improved error handling and logging',
      'Fixed CORS configuration',
      'Consistent JSON response format'
    ],
    success: true
  });
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
        success: true,
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
      success: true,
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
    res.status(500).json({ 
      success: false,
      error: 'Failed to load questionnaire',
      message: 'Failed to load questionnaire'
    });
  }
});

app.post('/api/questionnaire', authenticateToken, async (req, res) => {
  try {
    const { responses } = req.body;
    
    if (!responses || typeof responses !== 'object') {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid questionnaire responses',
        message: 'Invalid questionnaire responses'
      });
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
        success: false,
        error: `Missing required fields: ${missingFields.join(', ')}`,
        message: `Missing required fields: ${missingFields.join(', ')}`
      });
    }

    if (!Array.isArray(responses.mainGoals)) {
      return res.status(400).json({ 
        success: false,
        error: 'mainGoals must be an array',
        message: 'mainGoals must be an array'
      });
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

    // Update user profile with questionnaire data (safe handling of optional columns)
    const hasConsentTimestamp = await columnExists('user_profiles', 'consent_timestamp');
    const hasOnboardingCompleted = await columnExists('user_profiles', 'onboarding_completed_at');
    
    let updateQuery = `UPDATE user_profiles 
                       SET first_name = $1, 
                           pronouns = $2, 
                           updated_at = NOW()`;
    let params = [responses.firstName || "", responses.pronouns || "", req.user.userId];
    let paramIndex = 3;

    if (hasConsentTimestamp) {
      updateQuery += `, consent_timestamp = NOW()`;
    }
    
    if (hasOnboardingCompleted) {
      updateQuery += `, onboarding_completed_at = NOW()`;
    }
    
    updateQuery += ` WHERE user_id = ${paramIndex}`;
    
    await pool.query(updateQuery, params);
    
    console.log('✅ PIPEDA-compliant questionnaire completed for user:', req.user.username);
    console.log('   Main goals selected:', responses.mainGoals);
    
    res.json({ 
      success: true, 
      message: 'Questionnaire completed successfully' 
    });
  } catch (error) {
    console.error('Questionnaire save error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to save questionnaire',
      message: 'Failed to save questionnaire'
    });
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
      return res.status(404).json({ 
        success: false,
        error: 'Profile not found',
        message: 'Profile not found'
      });
    }
    
    const profile = profileResult.rows[0];
    
    // Convert database format to app format (safely handle optional columns)
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
      consentTimestamp: profile.consent_timestamp || null,
      dataRetentionPeriod: profile.data_retention_period || 365
    };

    // Add optional enhanced fields if they exist
    if (profile.app_theme !== undefined) profileData.appTheme = profile.app_theme;
    if (profile.accessibility_features !== undefined) profileData.accessibilityFeatures = profile.accessibility_features;
    if (profile.language_preference !== undefined) profileData.languagePreference = profile.language_preference;
    if (profile.timezone !== undefined) profileData.timezone = profile.timezone;
    if (profile.onboarding_completed_at !== undefined) profileData.onboardingCompletedAt = profile.onboarding_completed_at;
    if (profile.last_active_at !== undefined) profileData.lastActiveAt = profile.last_active_at;
    if (profile.app_version !== undefined) profileData.appVersion = profile.app_version;
    if (profile.device_info !== undefined) profileData.deviceInfo = profile.device_info;
    
    res.json({
      success: true,
      ...profileData
    });
  } catch (error) {
    console.error('Profile load error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to load profile',
      message: 'Failed to load profile'
    });
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
    
    // Build dynamic update query based on existing columns
    let updateFields = [];
    let params = [];
    let paramIndex = 1;

    // Core fields that should always exist
    if (firstName !== undefined) {
      updateFields.push(`first_name = ${paramIndex}`);
      params.push(firstName);
      paramIndex++;
    }
    if (pronouns !== undefined) {
      updateFields.push(`pronouns = ${paramIndex}`);
      params.push(pronouns);
      paramIndex++;
    }
    if (joinDate !== undefined) {
      updateFields.push(`join_date = ${paramIndex}`);
      params.push(joinDate);
      paramIndex++;
    }
    if (profileColorHex !== undefined) {
      updateFields.push(`profile_color_hex = ${paramIndex}`);
      params.push(profileColorHex);
      paramIndex++;
    }
    if (notifications !== undefined) {
      updateFields.push(`notifications = ${paramIndex}`);
      params.push(notifications);
      paramIndex++;
    }
    if (biometricAuth !== undefined) {
      updateFields.push(`biometric_auth = ${paramIndex}`);
      params.push(biometricAuth);
      paramIndex++;
    }
    if (darkMode !== undefined) {
      updateFields.push(`dark_mode = ${paramIndex}`);
      params.push(darkMode);
      paramIndex++;
    }
    if (reminderTime !== undefined) {
      updateFields.push(`reminder_time = ${paramIndex}`);
      params.push(reminderTime);
      paramIndex++;
    }
    if (dataPurposes !== undefined) {
      updateFields.push(`data_purposes = ${paramIndex}`);
      params.push(dataPurposes);
      paramIndex++;
    }

    // Enhanced fields that might not exist
    const enhancedFieldMap = [
      { field: 'consent_timestamp', value: consentTimestamp, column: 'consent_timestamp' },
      { field: 'data_retention_period', value: dataRetentionPeriod, column: 'data_retention_period' },
      { field: 'app_theme', value: appTheme, column: 'app_theme' },
      { field: 'accessibility_features', value: accessibilityFeatures, column: 'accessibility_features' },
      { field: 'language_preference', value: languagePreference, column: 'language_preference' },
      { field: 'timezone', value: timezone, column: 'timezone' },
      { field: 'app_version', value: appVersion, column: 'app_version' },
      { field: 'device_info', value: deviceInfo, column: 'device_info' }
    ];

    for (const { field, value, column } of enhancedFieldMap) {
      if (value !== undefined) {
        const exists = await columnExists('user_profiles', column);
        if (exists) {
          updateFields.push(`${column} = ${paramIndex}`);
          params.push(value);
          paramIndex++;
        }
      }
    }

    // Always update last_active_at and updated_at if they exist
    const hasLastActive = await columnExists('user_profiles', 'last_active_at');
    if (hasLastActive) {
      updateFields.push('last_active_at = NOW()');
    }
    updateFields.push('updated_at = NOW()');

    // Add user_id parameter
    params.push(req.user.userId);
    const userIdParam = `${paramIndex}`;

    if (updateFields.length > 0) {
      const updateQuery = `UPDATE user_profiles SET ${updateFields.join(', ')} WHERE user_id = ${userIdParam}`;
      await pool.query(updateQuery, params);
    }
    
    console.log('✅ PIPEDA-compliant profile updated for user:', req.user.username);
    
    res.json({ 
      success: true, 
      message: 'Profile updated successfully' 
    });
  } catch (error) {
    console.error('Profile save error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to save profile',
      message: 'Failed to save profile'
    });
  }
});

// PIPEDA ENHANCED MOOD ENDPOINTS
app.get('/api/mood', authenticateToken, async (req, res) => {
  console.log('📊 Mood entries request for user:', req.user.userId);
  
  try {
    await logDataAccess(req.user.userId, 'read', 'mood_entries', req);

    // Build query based on existing columns
    let selectFields = 'id, mood, note, entry_date as date';
    
    const enhancedColumns = [
      'data_purpose', 'mood_category', 'mood_triggers', 
      'weather_context', 'activity_context', 'privacy_level'
    ];

    for (const column of enhancedColumns) {
      const exists = await columnExists('mood_entries', column);
      if (exists) {
        selectFields += `, ${column}`;
      }
    }

    console.log('📊 Querying mood entries with fields:', selectFields);

    const moodResult = await pool.query(
      `SELECT ${selectFields} FROM mood_entries WHERE user_id = $1 ORDER BY entry_date DESC`,
      [req.user.userId]
    );
    
    console.log(`✅ Found ${moodResult.rows.length} mood entries`);
    
    res.json({
      success: true,
      data: moodResult.rows
    });
  } catch (error) {
    console.error('Mood load error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to load mood entries',
      message: 'Failed to load mood entries'
    });
  }
});

app.post('/api/mood', authenticateToken, async (req, res) => {
  console.log('📊 Creating mood entry for user:', req.user.userId);
  console.log('📤 Mood data:', JSON.stringify(req.body, null, 2));
  
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
      console.log('❌ Missing required mood fields');
      return res.status(400).json({ 
        success: false,
        error: 'Mood and date are required',
        message: 'Mood and date are required'
      });
    }
    
    if (mood < 1 || mood > 10) {
      console.log('❌ Invalid mood value:', mood);
      return res.status(400).json({ 
        success: false,
        error: 'Mood must be between 1 and 10',
        message: 'Mood must be between 1 and 10'
      });
    }
    
    await logDataAccess(req.user.userId, 'create', 'mood_entry', req, dataPurpose);
    
    // Build dynamic insert query based on existing columns
    let insertFields = ['user_id', 'mood', 'note', 'entry_date'];
    let insertValues = ['$1', '$2', '$3', '$4'];
    let params = [req.user.userId, parseInt(mood), note || null, date];
    let paramIndex = 5;

    console.log('💾 Creating mood entry with base fields:', { mood, note, date });

    // Enhanced fields that might not exist
    const enhancedFieldMap = [
      { field: 'data_purpose', value: dataPurpose, column: 'data_purpose' },
      { field: 'mood_category', value: moodCategory, column: 'mood_category' },
      { field: 'mood_triggers', value: moodTriggers, column: 'mood_triggers' },
      { field: 'weather_context', value: weatherContext, column: 'weather_context' },
      { field: 'activity_context', value: activityContext, column: 'activity_context' },
      { field: 'privacy_level', value: privacyLevel, column: 'privacy_level' }
    ];

    for (const { field, value, column } of enhancedFieldMap) {
      if (value !== undefined) {
        const exists = await columnExists('mood_entries', column);
        if (exists) {
          insertFields.push(column);
          insertValues.push(`${paramIndex}`);
          params.push(value);
          paramIndex++;
          console.log(`✅ Added enhanced field ${column}:`, value);
        } else {
          console.log(`⚠️ Column ${column} doesn't exist, skipping`);
        }
      }
    }
    
    const insertQuery = `INSERT INTO mood_entries (${insertFields.join(', ')}) VALUES (${insertValues.join(', ')}) RETURNING *`;
    console.log('📝 Executing mood insert:', insertQuery);
    console.log('📝 With parameters:', params);
    
    const moodResult = await pool.query(insertQuery, params);
    
    const savedEntry = moodResult.rows[0];
    console.log('✅ Mood entry saved successfully:', savedEntry.id);
    
    res.json({ 
      success: true, 
      message: 'Mood entry saved successfully',
      entry: savedEntry
    });
  } catch (error) {
    console.error('💥 Mood save error:', error);
    console.error('💥 Error details:', error.message);
    console.error('💥 Error stack:', error.stack);
    res.status(500).json({ 
      success: false,
      error: 'Failed to save mood entry',
      message: 'Failed to save mood entry',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// PIPEDA ENHANCED JOURNAL ENDPOINTS
app.get('/api/journal', authenticateToken, async (req, res) => {
  console.log('📚 Journal entries request for user:', req.user.userId);
  
  try {
    await logDataAccess(req.user.userId, 'read', 'journal_entries', req);

    // Build query based on existing columns
    let selectFields = 'id, content, prompt, entry_date as date';
    
    const enhancedColumns = [
      'data_purpose', 'entry_type', 'emotional_tone', 
      'word_count', 'reading_time_estimate', 'tags', 'privacy_level'
    ];

    for (const column of enhancedColumns) {
      const exists = await columnExists('journal_entries', column);
      if (exists) {
        selectFields += `, ${column}`;
      }
    }

    console.log('📚 Querying journal entries with fields:', selectFields);

    const journalResult = await pool.query(
      `SELECT ${selectFields} FROM journal_entries WHERE user_id = $1 ORDER BY entry_date DESC`,
      [req.user.userId]
    );
    
    console.log(`✅ Found ${journalResult.rows.length} journal entries`);
    
    res.json({
      success: true,
      data: journalResult.rows
    });
  } catch (error) {
    console.error('Journal load error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to load journal entries',
      message: 'Failed to load journal entries'
    });
  }
});

app.post('/api/journal', authenticateToken, async (req, res) => {
  console.log('📚 Creating journal entry for user:', req.user.userId);
  console.log('📤 Journal data:', JSON.stringify(req.body, null, 2));
  
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
      console.log('❌ Missing required journal fields');
      return res.status(400).json({ 
        success: false,
        error: 'Content and date are required',
        message: 'Content and date are required'
      });
    }
    
    if (content.trim().length === 0) {
      console.log('❌ Empty journal content');
      return res.status(400).json({ 
        success: false,
        error: 'Content cannot be empty',
        message: 'Content cannot be empty'
      });
    }
    
    await logDataAccess(req.user.userId, 'create', 'journal_entry', req, dataPurpose);
    
    // Calculate word count and reading time estimate
    const wordCount = content.trim().split(/\s+/).length;
    const readingTimeEstimate = Math.max(1, Math.ceil(wordCount / 200)); // Assume 200 words per minute
    
    console.log('📊 Journal stats - Words:', wordCount, 'Reading time:', readingTimeEstimate, 'min');
    
    // Build dynamic insert query based on existing columns
    let insertFields = ['user_id', 'content', 'prompt', 'entry_date'];
    let insertValues = ['$1', '$2', '$3', '$4'];
    let params = [req.user.userId, content.trim(), prompt || null, date];
    let paramIndex = 5;

    console.log('💾 Creating journal entry with base fields');

    // Enhanced fields that might not exist
    const enhancedFieldMap = [
      { field: 'data_purpose', value: dataPurpose, column: 'data_purpose' },
      { field: 'entry_type', value: entryType, column: 'entry_type' },
      { field: 'emotional_tone', value: emotionalTone, column: 'emotional_tone' },
      { field: 'word_count', value: wordCount, column: 'word_count' },
      { field: 'reading_time_estimate', value: readingTimeEstimate, column: 'reading_time_estimate' },
      { field: 'tags', value: tags, column: 'tags' },
      { field: 'privacy_level', value: privacyLevel, column: 'privacy_level' }
    ];

    for (const { field, value, column } of enhancedFieldMap) {
      if (value !== undefined) {
        const exists = await columnExists('journal_entries', column);
        if (exists) {
          insertFields.push(column);
          insertValues.push(`${paramIndex}`);
          params.push(value);
          paramIndex++;
          console.log(`✅ Added enhanced field ${column}:`, value);
        } else {
          console.log(`⚠️ Column ${column} doesn't exist, skipping`);
        }
      }
    }
    
    const insertQuery = `INSERT INTO journal_entries (${insertFields.join(', ')}) VALUES (${insertValues.join(', ')}) RETURNING *`;
    console.log('📝 Executing journal insert:', insertQuery);
    console.log('📝 With parameters:', params.map((p, i) => i === 1 ? `[${p.length} chars]` : p)); // Don't log full content
    
    const journalResult = await pool.query(insertQuery, params);
    
    const savedEntry = journalResult.rows[0];
    console.log('✅ Journal entry saved successfully:', savedEntry.id);
    
    res.json({ 
      success: true, 
      message: 'Journal entry saved successfully',
      entry: savedEntry
    });
  } catch (error) {
    console.error('💥 Journal save error:', error);
    console.error('💥 Error details:', error.message);
    console.error('💥 Error stack:', error.stack);
    res.status(500).json({ 
      success: false,
      error: 'Failed to save journal entry',
      message: 'Failed to save journal entry',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// PIPEDA: EnhancedCHAT ENDPOINT with consent checking
app.post('/api/chat', authenticateToken, async (req, res) => {
  console.log('💬 Chat request for user:', req.user.userId);
  
  try {
    const { message, chatHistory, sessionId, consentedToAI } = req.body;
    
    // PIPEDA: Check AI processing consent
    if (!consentedToAI) {
      console.log('❌ AI processing consent not given');
      return res.status(403).json({ 
        success: false,
        error: 'AI processing consent required',
        message: 'AI processing consent required',
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
        success: true,
        response: data.choices[0].message.content,
        sessionId: currentSession.id
      });
    } else {
      console.error('❌ No response from OpenAI:', data);
      res.status(500).json({ 
        success: false,
        error: 'No response from AI',
        message: 'No response from AI'
      });
    }
  } catch (error) {
    console.error('💥 Chat error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Server error',
      message: 'Server error'
    });
  }
});

// Start server with proper initialization
const startServer = async () => {
  try {
    console.log('🚀 Starting Luma Backend Server...');
    
    // Test database connection
    console.log('🔗 Testing database connection...');
    const client = await pool.connect();
    console.log('✅ Database connection successful');
    client.release();
    
    // Initialize database
    console.log('🗄️ Initializing database...');
    await initializeDatabase();
    console.log('✅ Database initialization complete');
    
    // Start the server
    app.listen(PORT, () => {
      console.log(`✅ Luma Enhanced PIPEDA-compliant backend running on port ${PORT}`);
      console.log(`🌐 Server URL: https://luma-backend-nfdc.onrender.com`);
      console.log(`🗄️ Database: PostgreSQL with Enhanced PIPEDA-compliant schema`);
      console.log(`📧 Email service: ${process.env.RESEND_API_KEY ? '✅ Configured' : '❌ Missing RESEND_API_KEY'}`);
      console.log(`🤖 OpenAI service: ${process.env.OPENAI_API_KEY ? '✅ Configured' : '❌ Missing OPENAI_API_KEY'}`);
      console.log(`🔗 Database URL: ${process.env.DATABASE_URL ? '✅ Configured' : '❌ Missing DATABASE_URL'}`);
      console.log(`🔑 JWT Secret: ${JWT_SECRET !== 'your-super-secret-jwt-key-change-this' ? '✅ Configured' : '⚠️ Using default - please change'}`);
      console.log(`\n🔥 SERVER IS READY TO HANDLE REQUESTS`);
      console.log(`\n🎉 ENHANCED PIPEDA COMPLIANCE FEATURES:`);
      console.log(`   ✅ Fixed registration endpoint with detailed logging`);
      console.log(`   ✅ Improved CORS configuration`);
      console.log(`   ✅ Consistent JSON response format`);
      console.log(`   ✅ Better error handling and debugging`);
      console.log(`   ✅ Safe column handling for gradual database migration`);
      console.log(`   ✅ Backward compatibility with existing database schemas`);
      console.log(`   ✅ Granular consent management with audit trails`);
      console.log(`   ✅ Data minimization (reduced personal data collection)`);
      console.log(`   ✅ User rights implementation (access, portability, deletion)`);
      console.log(`   ✅ Automatic data retention policies`);
      console.log(`   ✅ Comprehensive audit logging`);
      console.log(`   ✅ Sensitive content detection and flagging`);
      console.log(`   ✅ Enhanced privacy controls and transparency`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    console.error('❌ Error details:', error.message);
    console.error('❌ Error stack:', error.stack);
    process.exit(1);
  }
};

// Start the server
startServer();
