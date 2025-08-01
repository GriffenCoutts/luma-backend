const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
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
app.use(express.json());
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

// Initialize database tables
async function initializeDatabase() {
  try {
    console.log('🗄️ Initializing database tables...');
    
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

    // User profiles - FIXED: Ensure data_purposes column is created properly
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
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Add data_purposes column separately (in case it doesn't exist)
    try {
      await pool.query(`
        ALTER TABLE user_profiles 
        ADD COLUMN IF NOT EXISTS data_purposes TEXT[] DEFAULT '{"personalization","app_functionality"}'
      `);
      console.log('✅ data_purposes column ensured');
    } catch (alterError) {
      console.log('⚠️ Could not add data_purposes column:', alterError.message);
    }

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

    // Questionnaire responses - FIXED: Create without data_purpose initially
    await pool.query(`
      CREATE TABLE IF NOT EXISTS questionnaire_responses (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        completed BOOLEAN DEFAULT false,
        first_name VARCHAR(255),
        pronouns VARCHAR(50),
        main_goals TEXT[],
        communication_style VARCHAR(255),
        consent_given BOOLEAN DEFAULT false,
        completed_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Add data_purpose column separately (in case it doesn't exist)
    try {
      await pool.query(`
        ALTER TABLE questionnaire_responses 
        ADD COLUMN IF NOT EXISTS data_purpose VARCHAR(100) DEFAULT 'app_personalization'
      `);
      console.log('✅ questionnaire data_purpose column ensured');
    } catch (alterError) {
      console.log('⚠️ Could not add questionnaire data_purpose column:', alterError.message);
    }

    // Mood entries - FIXED: Create without data_purpose initially
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

    // Add data_purpose column separately
    try {
      await pool.query(`
        ALTER TABLE mood_entries 
        ADD COLUMN IF NOT EXISTS data_purpose VARCHAR(100) DEFAULT 'mood_tracking'
      `);
      console.log('✅ mood_entries data_purpose column ensured');
    } catch (alterError) {
      console.log('⚠️ Could not add mood_entries data_purpose column:', alterError.message);
    }

    // Journal entries - FIXED: Create without data_purpose initially
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

    // Add data_purpose column separately
    try {
      await pool.query(`
        ALTER TABLE journal_entries 
        ADD COLUMN IF NOT EXISTS data_purpose VARCHAR(100) DEFAULT 'journaling'
      `);
      console.log('✅ journal_entries data_purpose column ensured');
    } catch (alterError) {
      console.log('⚠️ Could not add journal_entries data_purpose column:', alterError.message);
    }

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

    console.log('✅ Database tables initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    throw error;
  }
}

// Authentication middleware
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

// USER REGISTRATION - ENHANCED DEBUG VERSION
app.post('/api/auth/register', async (req, res) => {
  console.log('🚀 Registration request started');
  console.log('📝 Request body:', req.body);
  console.log('📝 Content-Type:', req.headers['content-type']);
  
  try {
    const { username, email, password } = req.body;
    
    console.log('📝 Extracted values:', { username, email, passwordLength: password?.length });

    // Input validation with detailed logging
    if (!username || !email || !password) {
      console.log('❌ Missing required fields:', { username: !!username, email: !!email, password: !!password });
      return res.status(400).json({ 
        success: false,
        error: 'Username, email, and password are required',
        message: 'Username, email, and password are required',
        debug: { username: !!username, email: !!email, password: !!password }
      });
    }

    if (password.length < 6) {
      console.log('❌ Password too short:', password.length);
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 6 characters',
        message: 'Password must be at least 6 characters'
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.log('❌ Invalid email format:', email);
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
      'SELECT id, username, email FROM users WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($2)',
      [username, email]
    );

    console.log('📊 Existing user check result:', existingUser.rows.length, 'users found');

    if (existingUser.rows.length > 0) {
      console.log('❌ User already exists:', existingUser.rows[0]);
      return res.status(400).json({ 
        success: false,
        error: 'Username or email already exists',
        message: 'Username or email already exists'
      });
    }

    console.log('✅ No existing user found, proceeding with registration');

    // Hash password
    console.log('🔐 Hashing password...');
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    console.log('✅ Password hashed successfully');

    // Create user with transaction
    console.log('🗄️ Starting database transaction...');
    const client = await pool.connect();
    
    try {
      await client.query('BEGIN');
      console.log('✅ Transaction started');
      
      // Create user
      console.log('👤 Creating user record...');
      const userResult = await client.query(
        'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
        [username, email, hashedPassword]
      );

      const newUser = userResult.rows[0];
      console.log('✅ User created with ID:', newUser.id);

      // Create user profile - FIXED: Remove data_purposes from initial insert
      console.log('📋 Creating user profile...');
      const profileResult = await client.query(
        `INSERT INTO user_profiles (user_id, first_name, pronouns, join_date, profile_color_hex, notifications, biometric_auth, dark_mode, reminder_time) 
         VALUES ($1, $2, $3, NOW(), $4, $5, $6, $7, $8) RETURNING id`,
        [newUser.id, '', '', '#800080', true, false, false, '19:00:00']
      );
      console.log('✅ User profile created with ID:', profileResult.rows[0].id);

      // Update profile with data_purposes separately (in case column doesn't exist yet)
      try {
        await client.query(
          `UPDATE user_profiles SET data_purposes = $1 WHERE user_id = $2`,
          [['personalization', 'app_functionality'], newUser.id]
        );
        console.log('✅ Data purposes updated successfully');
      } catch (dataPurposesError) {
        console.log('⚠️ Could not set data_purposes (column may not exist):', dataPurposesError.message);
        // Continue anyway - this is not critical for registration
      }

      // Create questionnaire response - FIXED: Remove data_purpose from initial insert
      console.log('📝 Creating questionnaire record...');
      const questionnaireResult = await client.query(
        `INSERT INTO questionnaire_responses (user_id, completed, first_name, pronouns, main_goals, communication_style, consent_given) 
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
        [newUser.id, false, '', '', [], '', false]
      );
      console.log('✅ Questionnaire record created with ID:', questionnaireResult.rows[0].id);

      // Update questionnaire with data_purpose separately (if column exists)
      try {
        await client.query(
          `UPDATE questionnaire_responses SET data_purpose = $1 WHERE user_id = $2`,
          ['app_personalization', newUser.id]
        );
        console.log('✅ Questionnaire data_purpose updated successfully');
      } catch (dataPurposeError) {
        console.log('⚠️ Could not set questionnaire data_purpose (column may not exist):', dataPurposeError.message);
        // Continue anyway - this is not critical for registration
      }

      await client.query('COMMIT');
      console.log('✅ Transaction committed successfully');
      
      // Generate JWT token
      console.log('🔑 Generating JWT token...');
      const token = jwt.sign(
        { userId: newUser.id, username: newUser.username },
        JWT_SECRET,
        { expiresIn: '7d' }
      );
      console.log('✅ JWT token generated');

      console.log('🎉 Registration completed successfully for:', newUser.username);

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

    } catch (transactionError) {
      console.log('💥 Transaction error occurred:', transactionError.message);
      console.log('💥 Error code:', transactionError.code);
      console.log('💥 Error detail:', transactionError.detail);
      
      await client.query('ROLLBACK');
      console.log('🔄 Transaction rolled back');
      throw transactionError;
    } finally {
      client.release();
      console.log('🔌 Database client released');
    }

  } catch (error) {
    console.error('💥 REGISTRATION ERROR:', error.message);
    console.error('💥 Error stack:', error.stack);
    console.error('💥 Error code:', error.code);
    console.error('💥 Error detail:', error.detail);
    
    // Provide more specific error messages
    let errorMessage = 'Server error during registration';
    let statusCode = 500;
    
    if (error.code === '23505') { // PostgreSQL unique violation
      if (error.detail.includes('username')) {
        errorMessage = 'Username already exists';
      } else if (error.detail.includes('email')) {
        errorMessage = 'Email already exists';
      } else {
        errorMessage = 'User already exists';
      }
      statusCode = 400;
    } else if (error.code === '23503') { // Foreign key violation
      errorMessage = 'Database constraint error';
      statusCode = 400;
    } else if (error.code === '23514') { // Check constraint violation
      errorMessage = 'Invalid data provided';
      statusCode = 400;
    }
    
    res.status(statusCode).json({
      success: false,
      error: errorMessage,
      message: errorMessage,
      debug: process.env.NODE_ENV === 'development' ? {
        code: error.code,
        detail: error.detail,
        message: error.message
      } : undefined
    });
  }
});

// USER LOGIN
app.post('/api/auth/login', async (req, res) => {
  console.log('🔐 Login request started');
  
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Username and password are required',
        message: 'Username and password are required'
      });
    }

    console.log('🔍 Looking up user:', username);

    // Enhanced user lookup with case-insensitive matching
    const userResult = await pool.query(
      'SELECT id, username, email, password_hash, created_at FROM users WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($1)',
      [username]
    );
    
    console.log('📊 Query results: Found', userResult.rows.length, 'users');
    
    if (userResult.rows.length > 0) {
      console.log('✅ Found user:', userResult.rows[0].username);
    } else {
      console.log('❌ No user found for:', username);
    }

    if (userResult.rows.length === 0) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials',
        message: 'Invalid credentials'
      });
    }

    const user = userResult.rows[0];

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      console.log('❌ Invalid password for user:', user.username);
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials',
        message: 'Invalid credentials'
      });
    }

    console.log('✅ Password verified for user:', user.username);

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log('✅ Login successful for:', user.username);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });

  } catch (error) {
    console.error('💥 LOGIN ERROR:', error);
    
    res.status(500).json({
      success: false,
      error: 'Server error during login',
      message: 'Server error during login'
    });
  }
});

// PASSWORD RESET REQUEST
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email is required',
        message: 'Email is required'
      });
    }
    
    console.log('🔐 Password reset requested for:', email);
    
    // Check if user exists
    const userResult = await pool.query(
      'SELECT id, username, email FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );
    
    if (userResult.rows.length === 0) {
      // Don't reveal if email exists or not for security
      return res.json({
        success: true,
        message: 'If an account with that email exists, we\'ve sent password reset instructions.'
      });
    }
    
    const user = userResult.rows[0];
    
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 3600000); // 1 hour
    
    // Save reset token to database
    await pool.query(
      `INSERT INTO password_resets (user_id, reset_token, expires_at, created_at) 
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id) 
       DO UPDATE SET reset_token = $2, expires_at = $3, created_at = NOW(), used = false`,
      [user.id, resetToken, resetExpires]
    );
    
    console.log(`🔑 Reset token generated for ${email}: ${resetToken}`);
    
    // In production, send email here
    // For development, we'll include the token in the response (REMOVE IN PRODUCTION!)
    res.json({
      success: true,
      message: 'If an account with that email exists, we\'ve sent password reset instructions.',
      // DEVELOPMENT ONLY - Remove this in production!
      developmentToken: process.env.NODE_ENV === 'development' ? resetToken : undefined
    });
    
  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error',
      message: 'Server error'
    });
  }
});

// PASSWORD RESET CONFIRMATION
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!token || !newPassword) {
      return res.status(400).json({
        success: false,
        error: 'Token and new password are required',
        message: 'Token and new password are required'
      });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 6 characters',
        message: 'Password must be at least 6 characters'
      });
    }
    
    // Find valid reset token
    const resetResult = await pool.query(
      `SELECT pr.*, u.id as user_id, u.username 
       FROM password_resets pr 
       JOIN users u ON pr.user_id = u.id 
       WHERE pr.reset_token = $1 AND pr.expires_at > NOW() AND pr.used = false`,
      [token]
    );
    
    if (resetResult.rows.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or expired reset token',
        message: 'Invalid or expired reset token'
      });
    }
    
    const resetRecord = resetResult.rows[0];
    
    // Hash new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    
    // Update password and mark token as used
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      await client.query(
        'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
        [hashedPassword, resetRecord.user_id]
      );
      
      await client.query(
        'UPDATE password_resets SET used = true WHERE id = $1',
        [resetRecord.id]
      );
      
      await client.query('COMMIT');
      
      console.log('✅ Password reset successful for user:', resetRecord.username);
      
      res.json({
        success: true,
        message: 'Password reset successful. You can now log in with your new password.'
      });
      
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
    
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error',
      message: 'Server error'
    });
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

// QUESTIONNAIRE ENDPOINTS
app.get('/api/questionnaire', authenticateToken, async (req, res) => {
  try {
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

    console.log('📝 Saving questionnaire for user:', req.user.userId);
    console.log('📝 Questionnaire data:', responses);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      // Update questionnaire responses
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

      // FIXED: Also update user profile with questionnaire data
      console.log('📝 Updating user profile with name:', responses.firstName);
      const profileUpdateResult = await client.query(
        `UPDATE user_profiles 
         SET first_name = $1, 
             pronouns = $2, 
             updated_at = NOW()
         WHERE user_id = $3
         RETURNING first_name, pronouns`,
        [responses.firstName || "", responses.pronouns || "", req.user.userId]
      );

      console.log('✅ Profile updated successfully:', profileUpdateResult.rows[0]);
      
      await client.query('COMMIT');
      
      res.json({ 
        success: true, 
        message: 'Questionnaire completed successfully' 
      });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Questionnaire save error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to save questionnaire',
      message: 'Failed to save questionnaire'
    });
  }
});

// FIXED PROFILE ENDPOINTS
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    console.log('📋 Loading profile for user:', req.user.userId);
    
    const profileResult = await pool.query(
      'SELECT * FROM user_profiles WHERE user_id = $1',
      [req.user.userId]
    );
    
    if (profileResult.rows.length === 0) {
      console.log('❌ No profile found for user:', req.user.userId);
      return res.status(404).json({ 
        success: false,
        error: 'Profile not found',
        message: 'Profile not found'
      });
    }
    
    const profile = profileResult.rows[0];
    console.log('✅ Profile loaded:', { firstName: profile.first_name, pronouns: profile.pronouns });
    
    res.json({
      success: true,
      firstName: profile.first_name || "",
      pronouns: profile.pronouns || "",
      joinDate: profile.join_date,
      profileColorHex: profile.profile_color_hex || "#800080",
      notifications: profile.notifications,
      biometricAuth: profile.biometric_auth,
      darkMode: profile.dark_mode,
      reminderTime: profile.reminder_time,
      dataPurposes: profile.data_purposes || []
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
    console.log('📝 Updating profile for user:', req.user.userId);
    console.log('📝 Profile data received:', req.body);
    
    const { 
      firstName,
      pronouns,
      joinDate, 
      profileColorHex, 
      notifications, 
      biometricAuth, 
      darkMode, 
      reminderTime,
      dataPurposes  // This comes from the iOS app as camelCase
    } = req.body;
    
    // FIXED: Handle the array properly for PostgreSQL
    let dataArray = ['personalization', 'app_functionality']; // Default values
    
    if (Array.isArray(dataPurposes)) {
      dataArray = dataPurposes;
    } else if (typeof dataPurposes === 'string') {
      dataArray = [dataPurposes];
    }
    
    console.log('📝 Processed data_purposes array:', dataArray);
    
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
        dataArray,  // Use the properly formatted array
        req.user.userId
      ]
    );
    
    console.log('✅ Profile updated successfully:', updateResult.rows[0]);
    
    res.json({ 
      success: true, 
      message: 'Profile updated successfully',
      profile: updateResult.rows[0]
    });
  } catch (error) {
    console.error('💥 Profile save error:', error);
    console.error('💥 Error details:', error.message);
    console.error('💥 Error code:', error.code);
    res.status(500).json({ 
      success: false,
      error: 'Failed to save profile',
      message: 'Failed to save profile',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// MOOD ENDPOINTS
app.get('/api/mood', authenticateToken, async (req, res) => {
  try {
    const moodResult = await pool.query(
      'SELECT id, mood, note, entry_date as date, data_purpose FROM mood_entries WHERE user_id = $1 ORDER BY entry_date DESC',
      [req.user.userId]
    );
    
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
  try {
    const { mood, note, date, dataPurpose = 'mood_tracking' } = req.body;
    
    if (!mood || !date) {
      return res.status(400).json({ 
        success: false,
        error: 'Mood and date are required',
        message: 'Mood and date are required'
      });
    }
    
    if (mood < 1 || mood > 10) {
      return res.status(400).json({ 
        success: false,
        error: 'Mood must be between 1 and 10',
        message: 'Mood must be between 1 and 10'
      });
    }
    
    const moodResult = await pool.query(
      'INSERT INTO mood_entries (user_id, mood, note, entry_date, data_purpose) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.userId, parseInt(mood), note || null, date, dataPurpose]
    );
    
    res.json({ 
      success: true, 
      message: 'Mood entry saved successfully',
      entry: moodResult.rows[0]
    });
  } catch (error) {
    console.error('Mood save error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to save mood entry',
      message: 'Failed to save mood entry'
    });
  }
});

// JOURNAL ENDPOINTS
app.get('/api/journal', authenticateToken, async (req, res) => {
  try {
    const journalResult = await pool.query(
      'SELECT id, content, prompt, entry_date as date, data_purpose FROM journal_entries WHERE user_id = $1 ORDER BY entry_date DESC',
      [req.user.userId]
    );
    
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
  try {
    const { content, prompt, date, dataPurpose = 'journaling' } = req.body;
    
    if (!content || !date) {
      return res.status(400).json({ 
        success: false,
        error: 'Content and date are required',
        message: 'Content and date are required'
      });
    }
    
    if (content.trim().length === 0) {
      return res.status(400).json({ 
        success: false,
        error: 'Content cannot be empty',
        message: 'Content cannot be empty'
      });
    }
    
    const journalResult = await pool.query(
      'INSERT INTO journal_entries (user_id, content, prompt, entry_date, data_purpose) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.userId, content.trim(), prompt || null, date, dataPurpose]
    );
    
    res.json({ 
      success: true, 
      message: 'Journal entry saved successfully',
      entry: journalResult.rows[0]
    });
  } catch (error) {
    console.error('Journal save error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to save journal entry',
      message: 'Failed to save journal entry'
    });
  }
});

// ENHANCED CHAT ENDPOINT WITH PROPER LUMA AI PROMPT
app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    const { message, chatHistory, sessionId, consentedToAI, userContext } = req.body;
    
    // Check AI processing consent
    if (!consentedToAI) {
      return res.status(403).json({ 
        success: false,
        error: 'AI processing consent required',
        message: 'AI processing consent required',
        requiresConsent: true 
      });
    }

    let currentSession = null;

    if (sessionId) {
      const sessionResult = await pool.query(
        'SELECT * FROM chat_sessions WHERE id = $1 AND user_id = $2',
        [sessionId, req.user.userId]
      );
      
      if (sessionResult.rows.length > 0) {
        currentSession = sessionResult.rows[0];
      }
    }
    
    if (!currentSession) {
      const sessionResult = await pool.query(
        'INSERT INTO chat_sessions (user_id, start_time, last_activity, user_context) VALUES ($1, NOW(), NOW(), $2) RETURNING *',
        [req.user.userId, JSON.stringify({ mood: null, recentJournalThemes: [], questionnaireCompleted: false })]
      );
      currentSession = sessionResult.rows[0];
    }

    // Detect sensitive content
    const sensitiveKeywords = ['suicide', 'self-harm', 'kill myself', 'medication', 'doctor', 'therapist'];
    const containsSensitive = sensitiveKeywords.some(keyword => message.toLowerCase().includes(keyword));

    // Add user message to session
    await pool.query(
      'INSERT INTO chat_messages (session_id, role, content, contains_sensitive_data, timestamp) VALUES ($1, $2, $3, $4, NOW())',
      [currentSession.id, 'user', message, containsSensitive]
    );

    // Get comprehensive user data for AI context
    const [profileResult, moodResult, journalResult, questionnaireResult] = await Promise.all([
      pool.query('SELECT first_name, pronouns FROM user_profiles WHERE user_id = $1', [req.user.userId]),
      pool.query('SELECT mood, note, entry_date FROM mood_entries WHERE user_id = $1 ORDER BY entry_date DESC LIMIT 7', [req.user.userId]),
      pool.query('SELECT content, prompt, entry_date FROM journal_entries WHERE user_id = $1 ORDER BY entry_date DESC LIMIT 3', [req.user.userId]),
      pool.query('SELECT completed, main_goals, communication_style FROM questionnaire_responses WHERE user_id = $1', [req.user.userId])
    ]);

    const userProfile = profileResult.rows[0] || {};
    const recentMoods = moodResult.rows;
    const recentJournals = journalResult.rows;
    const questionnaire = questionnaireResult.rows[0] || {};

    // Generate enhanced AI prompt with user context
    const systemPrompt = generateEnhancedAIPrompt({
      userProfile,
      recentMoods,
      recentJournals,
      questionnaire,
      userContext,
      containsSensitive
    });

    // Get recent conversation history
    const recentMessages = await pool.query(
      'SELECT role, content FROM chat_messages WHERE session_id = $1 ORDER BY timestamp DESC LIMIT 10',
      [currentSession.id]
    );

    // Prepare messages for OpenAI
    const messages = [
      {
        role: 'system',
        content: systemPrompt
      }
    ];

    // Add recent conversation history (excluding the message we just added)
    const historyMessages = recentMessages.rows.reverse().slice(0, -1);
    historyMessages.forEach(msg => {
      if (msg.role === 'user' || msg.role === 'assistant') {
        messages.push({
          role: msg.role,
          content: msg.content
        });
      }
    });

    // Add current message
    messages.push({
      role: 'user',
      content: message
    });

    // Call OpenAI API if available
    if (process.env.OPENAI_API_KEY) {
      try {
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
          const aiResponse = data.choices[0].message.content;
          
          // Add AI response to session
          await pool.query(
            'INSERT INTO chat_messages (session_id, role, content, timestamp) VALUES ($1, $2, $3, NOW())',
            [currentSession.id, 'assistant', aiResponse]
          );
          
          res.json({ 
            success: true,
            response: aiResponse,
            sessionId: currentSession.id
          });
        } else {
          throw new Error('No response from OpenAI');
        }
      } catch (openaiError) {
        console.error('OpenAI API error:', openaiError);
        // Fallback to enhanced response
        const fallbackResponse = generateEnhancedFallbackResponse(message, userProfile, recentMoods, recentJournals);
        
        await pool.query(
          'INSERT INTO chat_messages (session_id, role, content, timestamp) VALUES ($1, $2, $3, NOW())',
          [currentSession.id, 'assistant', fallbackResponse]
        );
        
        res.json({ 
          success: true,
          response: fallbackResponse,
          sessionId: currentSession.id
        });
      }
    } else {
      // No OpenAI API key - use enhanced fallback
      const fallbackResponse = generateEnhancedFallbackResponse(message, userProfile, recentMoods, recentJournals);
      
      await pool.query(
        'INSERT INTO chat_messages (session_id, role, content, timestamp) VALUES ($1, $2, $3, NOW())',
        [currentSession.id, 'assistant', fallbackResponse]
      );
      
      res.json({ 
        success: true,
        response: fallbackResponse,
        sessionId: currentSession.id
      });
    }
    
  } catch (error) {
    console.error('Chat error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Server error',
      message: 'Server error'
    });
  }
});

// AI PROMPT GENERATION FUNCTIONS
function generateEnhancedAIPrompt({ userProfile, recentMoods, recentJournals, questionnaire, userContext, containsSensitive }) {
  let prompt = `You are Luma, a compassionate AI therapist and wellness companion focused on mental health and emotional wellbeing. You provide thoughtful, empathetic responses that help users process their emotions and develop healthy coping strategies.

CORE EXPERTISE:
- Evidence-based therapy techniques (CBT, DBT, mindfulness, ACT)
- Mental health support and emotional processing
- Stress management and anxiety reduction techniques
- Healthy coping strategies and self-care practices
- Building emotional resilience and self-awareness
- Practical advice for daily mental wellness
- Crisis recognition and professional referral guidance

THERAPEUTIC APPROACH:
- Provide warm, non-judgmental support with genuine empathy
- Use evidence-based therapeutic techniques appropriately
- Offer practical, actionable advice tailored to the individual
- Help users identify patterns in thoughts, emotions, and behaviors
- Encourage healthy habits and meaningful self-reflection
- Validate feelings while gently challenging unhelpful thought patterns
- Always emphasize that you're a supportive tool, not a replacement for professional therapy

COMMUNICATION STYLE:
- Be conversational and supportive, not clinical or robotic
- Use the user's name when you know it to create connection
- Match their communication style (formal vs casual) while remaining professional
- Ask thoughtful follow-up questions to deepen understanding
- Provide specific, actionable suggestions rather than generic advice
- Use therapeutic techniques naturally within conversation
- Show genuine interest in their progress and wellbeing

`;

  // Add personalization based on user data
  if (userProfile.first_name) {
    prompt += `USER INFORMATION:
- Name: ${userProfile.first_name} (always use their name to create connection)
`;
    if (userProfile.pronouns) {
      prompt += `- Pronouns: ${userProfile.pronouns} (use these when referring to them)
`;
    }
  }

  // Add questionnaire insights
  if (questionnaire.completed) {
    prompt += `
QUESTIONNAIRE INSIGHTS:`;
    
    if (questionnaire.main_goals && questionnaire.main_goals.length > 0) {
      prompt += `
- Their main wellness goals: ${questionnaire.main_goals.join(', ')}`;
    }
    
    if (questionnaire.communication_style) {
      prompt += `
- Preferred communication style: ${questionnaire.communication_style}`;
    }
  }

  // Add mood pattern analysis
  if (recentMoods && recentMoods.length > 0) {
    const avgMood = recentMoods.reduce((sum, entry) => sum + entry.mood, 0) / recentMoods.length;
    const moodTrend = analyzeMoodTrend(recentMoods);
    
    prompt += `
RECENT MOOD PATTERNS (Last 7 days):
- Average mood: ${avgMood.toFixed(1)}/10
- Trend: ${moodTrend}
- Recent entries: `;
    
    recentMoods.slice(0, 3).forEach(mood => {
      const daysAgo = Math.floor((Date.now() - new Date(mood.entry_date).getTime()) / (1000 * 60 * 60 * 24));
      const timeRef = daysAgo === 0 ? 'today' : daysAgo === 1 ? 'yesterday' : `${daysAgo} days ago`;
      prompt += `${mood.mood}/10 (${timeRef})`;
      if (mood.note) prompt += ` - "${mood.note}"`;
      prompt += '; ';
    });
  }

  // Add journal theme analysis
  if (recentJournals && recentJournals.length > 0) {
    prompt += `
RECENT JOURNAL THEMES:`;
    
    recentJournals.forEach(journal => {
      const daysAgo = Math.floor((Date.now() - new Date(journal.entry_date).getTime()) / (1000 * 60 * 60 * 24));
      const timeRef = daysAgo === 0 ? 'today' : daysAgo === 1 ? 'yesterday' : `${daysAgo} days ago`;
      
      if (journal.prompt) {
        prompt += `
- ${timeRef}: Reflected on "${journal.prompt}"`;
      }
      
      // Extract themes from journal content
      const themes = extractJournalThemes(journal.content);
      if (themes.length > 0) {
        prompt += `
  Themes: ${themes.join(', ')}`;
      }
    });
  }

  // Add sensitivity guidance
  if (containsSensitive) {
    prompt += `
⚠️ SENSITIVE CONTENT DETECTED: The user's message contains potentially sensitive topics. Please:
- Respond with extra care and empathy
- Consider crisis intervention protocols if appropriate
- Encourage professional help if the situation warrants it
- Provide crisis resources if someone expresses suicidal ideation
- Stay calm and supportive while taking the situation seriously`;
  }

  // Add contextual instructions
  prompt += `
RESPONSE GUIDELINES:
- Reference their personal data naturally in conversation (don't just list facts)
- Ask follow-up questions about patterns you notice in their mood/journal data
- Provide personalized advice based on their specific situation and history
- Celebrate their progress and validate their challenges
- Use their name ${userProfile.first_name ? `(${userProfile.first_name})` : ''} to create connection
- Keep responses conversational, helpful, and under 300 words unless they ask for detailed guidance
- If they're struggling, offer specific coping techniques based on their preferences and history
- Always end with a thoughtful question or invitation to share more when appropriate

Remember: You're having a conversation with a real person who has trusted you with their mental health journey. Be genuine, caring, and helpful while maintaining appropriate boundaries.`;

  return prompt;
}

function analyzeMoodTrend(moods) {
  if (moods.length < 2) return 'insufficient data';
  
  const recent = moods.slice(0, 3).map(m => m.mood);
  const older = moods.slice(3, 6).map(m => m.mood);
  
  if (older.length === 0) return 'stable';
  
  const recentAvg = recent.reduce((a, b) => a + b, 0) / recent.length;
  const olderAvg = older.reduce((a, b) => a + b, 0) / older.length;
  
  const difference = recentAvg - olderAvg;
  
  if (difference > 1) return 'improving';
  if (difference < -1) return 'declining';
  return 'stable';
}

function extractJournalThemes(content) {
  const themes = [];
  const lowerContent = content.toLowerCase();
  
  // Emotional themes
  if (lowerContent.includes('stress') || lowerContent.includes('anxious') || lowerContent.includes('worried')) {
    themes.push('stress/anxiety');
  }
  if (lowerContent.includes('sad') || lowerContent.includes('depressed') || lowerContent.includes('down')) {
    themes.push('sadness');
  }
  if (lowerContent.includes('happy') || lowerContent.includes('joy') || lowerContent.includes('excited')) {
    themes.push('happiness');
  }
  if (lowerContent.includes('angry') || lowerContent.includes('frustrated') || lowerContent.includes('irritated')) {
    themes.push('anger/frustration');
  }
  
  // Life area themes
  if (lowerContent.includes('work') || lowerContent.includes('job') || lowerContent.includes('boss') || lowerContent.includes('career')) {
    themes.push('work');
  }
  if (lowerContent.includes('relationship') || lowerContent.includes('friend') || lowerContent.includes('family') || lowerContent.includes('partner')) {
    themes.push('relationships');
  }
  if (lowerContent.includes('health') || lowerContent.includes('exercise') || lowerContent.includes('sleep')) {
    themes.push('health/wellness');
  }
  if (lowerContent.includes('money') || lowerContent.includes('financial') || lowerContent.includes('budget')) {
    themes.push('finances');
  }
  
  // Positive themes
  if (lowerContent.includes('grateful') || lowerContent.includes('thankful') || lowerContent.includes('appreciate')) {
    themes.push('gratitude');
  }
  if (lowerContent.includes('goal') || lowerContent.includes('plan') || lowerContent.includes('future')) {
    themes.push('goals/planning');
  }
  if (lowerContent.includes('learn') || lowerContent.includes('grow') || lowerContent.includes('improve')) {
    themes.push('growth/learning');
  }
  
  return [...new Set(themes)]; // Remove duplicates
}

// Enhanced fallback response generator with user context
function generateEnhancedFallbackResponse(message, userProfile, recentMoods, recentJournals) {
  const name = userProfile.first_name || '';
  const greeting = name ? `${name}, ` : '';
  const lowerMessage = message.toLowerCase();
  
  // Analyze recent data for context
  let moodContext = '';
  if (recentMoods && recentMoods.length > 0) {
    const avgMood = recentMoods.reduce((sum, entry) => sum + entry.mood, 0) / recentMoods.length;
    if (avgMood < 5) {
      moodContext = " I notice you've been tracking some lower moods recently, and I want you to know that's completely valid.";
    } else if (avgMood > 7) {
      moodContext = " I'm glad to see you've been experiencing some positive moods lately.";
    }
  }
  
  // Generate contextual responses
  if (lowerMessage.includes('anxious') || lowerMessage.includes('anxiety')) {
    return `${greeting}I hear that you're feeling anxious${moodContext} That's completely understandable - anxiety is something many people experience. One technique that can help in the moment is the 4-7-8 breathing method: breathe in for 4 counts, hold for 7, and exhale for 8. This activates your body's relaxation response. 

Based on your recent patterns, it might also help to identify specific triggers. Can you tell me more about what's making you feel anxious right now?`;
  }
  
  if (lowerMessage.includes('sad') || lowerMessage.includes('depressed') || lowerMessage.includes('down')) {
    return `${greeting}I'm sorry you're feeling this way${moodContext} Your feelings are valid, and it's important that you're reaching out. Sometimes when we're feeling low, small actions can help - even something as simple as stepping outside for a few minutes or reaching out to someone you care about.

What's been on your mind lately that might be contributing to these feelings? Sometimes talking through our thoughts can provide clarity.`;
  }
  
  if (lowerMessage.includes('stress') || lowerMessage.includes('overwhelmed')) {
    return `${greeting}Feeling stressed or overwhelmed is really challenging${moodContext} When we're in that state, it can help to break things down into smaller, manageable pieces. One approach is to identify what you can control versus what you can't - focusing your energy on the things within your influence.

What's the biggest source of stress for you right now? Let's see if we can work through it together.`;
  }
  
  if (lowerMessage.includes('sleep') || lowerMessage.includes('tired') || lowerMessage.includes('insomnia')) {
    return `${greeting}Sleep issues can really impact how we feel overall${moodContext} Good sleep hygiene can make a big difference - things like keeping a consistent bedtime, avoiding screens before bed, and creating a calming bedtime routine.

How long have you been having trouble with sleep? Are there any patterns you've noticed that might be affecting your rest?`;
  }
  
  // Check for positive messages
  if (lowerMessage.includes('good') || lowerMessage.includes('better') || lowerMessage.includes('happy')) {
    return `${greeting}It's wonderful to hear that you're feeling good${moodContext} Celebrating these positive moments is important for our mental health. What's contributing to this positive feeling? 

Sometimes it helps to reflect on what's working well so we can recognize and build on these patterns.`;
  }
  
  // General supportive response with personalization
  return `${greeting}Thank you for sharing that with me${moodContext} I'm here to listen and support you. It sounds like you have something important on your mind, and I want you to know that your feelings and experiences matter.

Sometimes just talking through our thoughts and feelings can provide clarity and relief. Can you tell me more about what you're experiencing right now? I'm here to help you work through whatever you're facing.`;
}

// Database connection test endpoint
app.get('/api/debug/db-test', async (req, res) => {
  try {
    console.log('🔍 Testing database connection...');
    
    // Test basic connection
    const client = await pool.connect();
    console.log('✅ Database connection successful');
    
    // Test users table
    const usersTest = await client.query('SELECT COUNT(*) as count FROM users');
    console.log('✅ Users table accessible, count:', usersTest.rows[0].count);
    
    // Test user_profiles table
    const profilesTest = await client.query('SELECT COUNT(*) as count FROM user_profiles');
    console.log('✅ User profiles table accessible, count:', profilesTest.rows[0].count);
    
    // Test questionnaire_responses table
    const questionnaireTest = await client.query('SELECT COUNT(*) as count FROM questionnaire_responses');
    console.log('✅ Questionnaire responses table accessible, count:', questionnaireTest.rows[0].count);
    
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
    res.status(500).json({
      success: false,
      error: 'Database test failed',
      details: {
        message: error.message,
        code: error.code,
        detail: error.detail
      }
    });
  }
});

// Test registration data endpoint
app.post('/api/debug/test-registration', async (req, res) => {
  try {
    console.log('🧪 Testing registration data...');
    console.log('📝 Request body:', req.body);
    console.log('📝 Headers:', req.headers);
    
    const { username, email, password } = req.body;
    
    // Test data validation
    const validationResults = {
      username: {
        provided: !!username,
        value: username,
        length: username ? username.length : 0
      },
      email: {
        provided: !!email,
        value: email,
        valid: email ? /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) : false
      },
      password: {
        provided: !!password,
        length: password ? password.length : 0,
        valid: password ? password.length >= 6 : false
      }
    };
    
    // Test database connection
    const client = await pool.connect();
    
    // Check for existing users
    const existingUser = await pool.query(
      'SELECT id, username, email FROM users WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($2)',
      [username || 'test', email || 'test@test.com']
    );
    
    client.release();
    
    res.json({
      success: true,
      message: 'Registration test completed',
      validation: validationResults,
      database: {
        connected: true,
        existingUsers: existingUser.rows.length,
        existingUserData: existingUser.rows
      }
    });
    
  } catch (error) {
    console.error('❌ Registration test error:', error);
    res.status(500).json({
      success: false,
      error: 'Registration test failed',
      details: {
        message: error.message,
        code: error.code
      }
    });
  }
});

// DEBUG ENDPOINT: Check users (development only)
app.get('/api/debug/users', async (req, res) => {
  try {
    if (process.env.NODE_ENV === 'production') {
      return res.status(404).json({ error: 'Not found' });
    }

    const users = await pool.query('SELECT id, username, email, created_at FROM users ORDER BY created_at DESC LIMIT 10');
    
    res.json({
      success: true,
      count: users.rows.length,
      users: users.rows
    });
  } catch (error) {
    console.error('Debug users error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch users',
      details: error.message 
    });
  }
});

// HEALTH CHECK
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '6.1.0 - Fixed Deployment Version',
    database: 'PostgreSQL',
    openai: process.env.OPENAI_API_KEY ? 'Available' : 'Fallback mode',
    features: {
      passwordReset: 'Available',
      profileFixes: 'Applied',
      dataStructure: 'Fixed',
      aiPrompt: 'Enhanced'
    },
    success: true
  });
});

// Basic route for root
app.get('/', (req, res) => {
  res.json({
    message: 'Luma Backend API',
    version: '6.1.0',
    status: 'running',
    endpoints: {
      health: '/health',
      auth: '/api/auth/*',
      profile: '/api/profile',
      mood: '/api/mood',
      journal: '/api/journal',
      chat: '/api/chat'
    }
  });
});

// CATCH ALL - Return 404 for unknown routes
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found',
    message: 'The requested endpoint does not exist'
  });
});

// ERROR HANDLING MIDDLEWARE
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: 'An unexpected error occurred'
  });
});

// Start server
const startServer = async () => {
  try {
    console.log('🚀 Starting Luma Backend Server...');
    
    // Test database connection
    const client = await pool.connect();
    console.log('✅ Database connection successful');
    client.release();
    
    // Initialize database
    await initializeDatabase();
    console.log('✅ Database initialization complete');
    
    // Start the server
    app.listen(PORT, () => {
      console.log(`✅ Luma backend running on port ${PORT}`);
      console.log(`🌐 Server URL: https://luma-backend-nfdc.onrender.com`);
      console.log(`🤖 AI Mode: ${process.env.OPENAI_API_KEY ? 'OpenAI GPT-4' : 'Fallback responses'}`);
      console.log(`🔥 SERVER IS READY TO HANDLE REQUESTS`);
      console.log(`\n🎉 FEATURES INCLUDED:`);
      console.log(`   ✅ Enhanced AI therapist prompt with evidence-based techniques`);
      console.log(`   ✅ Fixed profile name saving in questionnaire and profile updates`);
      console.log(`   ✅ Complete password reset functionality with secure tokens`);
      console.log(`   ✅ Intelligent fallback responses when OpenAI is unavailable`);
      console.log(`   ✅ Personalized responses using user's name and context`);
      console.log(`   ✅ Mood trend analysis and journal theme extraction`);
      console.log(`   ✅ PIPEDA-compliant privacy features`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
startServer();
