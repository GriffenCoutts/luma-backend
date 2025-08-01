const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
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
        data_purposes TEXT[] DEFAULT '{"personalization","app_functionality"}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
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
        main_goals TEXT[],
        communication_style VARCHAR(255),
        data_purpose VARCHAR(100) DEFAULT 'app_personalization',
        consent_given BOOLEAN DEFAULT false,
        completed_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
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

// USER REGISTRATION
app.post('/api/auth/register', async (req, res) => {
  console.log('🚀 Registration request started');
  
  try {
    const { username, email, password } = req.body;

    // Input validation
    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Username, email, and password are required',
        message: 'Username, email, and password are required'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 6 characters',
        message: 'Password must be at least 6 characters'
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false,
        error: 'Please enter a valid email address',
        message: 'Please enter a valid email address'
      });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($2)',
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ 
        success: false,
        error: 'Username or email already exists',
        message: 'Username or email already exists'
      });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user with transaction
    const client = await pool.connect();
    
    try {
      await client.query('BEGIN');
      
      // Create user
      const userResult = await client.query(
        'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
        [username, email, hashedPassword]
      );

      const newUser = userResult.rows[0];

      // Create user profile
      await client.query(
        `INSERT INTO user_profiles (user_id, first_name, pronouns, join_date, profile_color_hex, notifications, biometric_auth, dark_mode, reminder_time, data_purposes) 
         VALUES ($1, '', '', NOW(), '#800080', true, false, false, '19:00:00', '{"personalization","app_functionality"}')`,
        [newUser.id]
      );

      // Create questionnaire response
      await client.query(
        `INSERT INTO questionnaire_responses (user_id, completed, first_name, pronouns, main_goals, communication_style, data_purpose, consent_given) 
         VALUES ($1, false, '', '', '{}', '', 'app_personalization', false)`,
        [newUser.id]
      );

      await client.query('COMMIT');
      
      // Generate JWT token
      const token = jwt.sign(
        { userId: newUser.id, username: newUser.username },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

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

    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

  } catch (error) {
    console.error('💥 REGISTRATION ERROR:', error);
    
    res.status(500).json({
      success: false,
      error: 'Server error during registration',
      message: 'Server error during registration'
    });
  }
});

// ENHANCED USER LOGIN
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
      
      // DEBUG: Check what users exist
      const allUsers = await pool.query('SELECT username, email FROM users LIMIT 5');
      console.log('📊 Users in database:', allUsers.rows);
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

    // FIXED: Update user profile with questionnaire data
    console.log('📝 Updating user profile with name:', responses.firstName);
    const profileUpdateResult = await pool.query(
      `UPDATE user_profiles 
       SET first_name = $1, 
           pronouns = $2, 
           updated_at = NOW()
       WHERE user_id = $3
       RETURNING first_name, pronouns`,
      [responses.firstName || "", responses.pronouns || "", req.user.userId]
    );

    console.log('✅ Profile updated successfully:', profileUpdateResult.rows[0]);
    
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

// PROFILE ENDPOINTS
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
      dataPurposes
    } = req.body;
    
    const updateResult = await pool.query(
      `UPDATE user_profiles 
       SET first_name = $1, 
           pronouns = $2, 
           join_date = $3,
           profile_color_hex = $4,
           notifications = $5,
           biometric_auth = $6,
           dark_mode = $7,
           reminder_time = $8,
           data_purposes = $9,
           updated_at = NOW()
       WHERE user_id = $10
       RETURNING first_name, pronouns`,
      [
        firstName || "",
        pronouns || "",
        joinDate || new Date(),
        profileColorHex || "#800080",
        notifications !== undefined ? notifications : true,
        biometricAuth !== undefined ? biometricAuth : false,
        darkMode !== undefined ? darkMode : false,
        reminderTime || "19:00:00",
        dataPurposes || [],
        req.user.userId
      ]
    );
    
    console.log('✅ Profile updated successfully:', updateResult.rows[0]);
    
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

    // Get user profile for personalization
    const profileResult = await pool.query(
      'SELECT first_name, pronouns FROM user_profiles WHERE user_id = $1',
      [req.user.userId]
    );

    const userProfile = profileResult.rows[0] || {};
    
    // Build context for AI
    let contextString = '';
    if (userProfile.first_name) {
      contextString += `The user's name is ${userProfile.first_name}. `;
    }
    if (userProfile.pronouns) {
      contextString += `Their pronouns are ${userProfile.pronouns}. `;
    }
    if (userContext) {
      contextString += `Additional context: ${userContext} `;
    }

    // Get recent conversation history
    const recentMessages = await pool.query(
      'SELECT role, content FROM chat_messages WHERE session_id = $1 ORDER BY timestamp DESC LIMIT 10',
      [currentSession.id]
    );

    // Prepare messages for OpenAI
    const messages = [
      {
        role: 'system',
        content: `You are Luma, a compassionate AI therapist and wellness companion focused on mental health and emotional wellbeing. You provide thoughtful, empathetic responses that help users process their emotions and develop healthy coping strategies.

Your expertise includes:
- Evidence-based therapy techniques (CBT, DBT, mindfulness)
- Mental health support and emotional processing  
- Stress management and anxiety reduction techniques
- Healthy coping strategies and self-care practices
- Building emotional resilience and self-awareness
- Practical advice for daily mental wellness
- Recognizing when professional help may be needed

Your approach:
- Provide warm, non-judgmental support
- Use evidence-based therapeutic techniques
- Offer practical, actionable advice
- Help users identify patterns in their thoughts and emotions
- Encourage healthy habits and self-reflection
- Always emphasize that you're a supportive tool, not a replacement for professional therapy when serious issues arise

Be warm, genuine, and focus on evidence-based mental health practices. Keep responses helpful, engaging, and grounded in psychological wellness principles.

${contextString ? `User context: ${contextString}` : ''}

Remember to be conversational and supportive, not clinical. Focus on understanding their experience first, then gently guide them toward insights and healthy coping strategies.`
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
        // Fallback to simple response
        const fallbackResponse = generateFallbackResponse(message, userProfile);
        
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
      // No OpenAI API key - use fallback
      const fallbackResponse = generateFallbackResponse(message, userProfile);
      
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

// Fallback response generator when OpenAI is not available
function generateFallbackResponse(message, userProfile) {
  const name = userProfile.first_name || '';
  const greeting = name ? `${name}, ` : '';
  
  const lowerMessage = message.toLowerCase();
  
  if (lowerMessage.includes('anxious') || lowerMessage.includes('anxiety')) {
    return `${greeting}I hear that you're feeling anxious. That's completely understandable - anxiety is something many people experience. One technique that can help in the moment is the 4-7-8 breathing method: breathe in for 4 counts, hold for 7, and exhale for 8. This activates your body's relaxation response. Can you tell me more about what's making you feel anxious right now?`;
  }
  
  if (lowerMessage.includes('sad') || lowerMessage.includes('depressed') || lowerMessage.includes('down')) {
    return `${greeting}I'm sorry you're feeling this way. Your feelings are valid, and it's important that you're reaching out. Sometimes when we're feeling low, small actions can help - even something as simple as stepping outside for a few minutes or reaching out to someone you care about. What's been on your mind lately that might be contributing to these feelings?`;
  }
  
  if (lowerMessage.includes('stress') || lowerMessage.includes('overwhelmed')) {
    return `${greeting}Feeling stressed or overwhelmed is really challenging. When we're in that state, it can help to break things down into smaller, manageable pieces. One approach is to identify what you can control versus what you can't - focusing your energy on the things within your influence. What's the biggest source of stress for you right now?`;
  }
  
  if (lowerMessage.includes('sleep') || lowerMessage.includes('tired') || lowerMessage.includes('insomnia')) {
    return `${greeting}Sleep issues can really impact how we feel overall. Good sleep hygiene can make a big difference - things like keeping a consistent bedtime, avoiding screens before bed, and creating a calming bedtime routine. How long have you been having trouble with sleep?`;
  }
  
  // General supportive response
  return `${greeting}Thank you for sharing that with me. I'm here to listen and support you. It sounds like you have something important on your mind. Sometimes just talking through our thoughts and feelings can provide clarity and relief. Can you tell me more about what you're experiencing right now?`;
}

// HEALTH CHECK
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '5.6.0 - Enhanced AI Prompt + Profile Fixes',
    database: 'PostgreSQL',
    openai: process.env.OPENAI_API_KEY ? 'Available' : 'Fallback mode',
    success: true
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
      console.log(`\n🎉 NEW FEATURES:`);
      console.log(`   ✅ Enhanced AI therapist prompt with evidence-based techniques`);
      console.log(`   ✅ Fixed profile name saving in questionnaire and profile updates`);
      console.log(`   ✅ Intelligent fallback responses when OpenAI is unavailable`);
      console.log(`   ✅ Personalized responses using user's name and context`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
startServer();
