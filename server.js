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
        name VARCHAR(255),
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        pronouns VARCHAR(50),
        age VARCHAR(10),
        birth_date DATE,
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

    // Questionnaire responses
    await pool.query(`
      CREATE TABLE IF NOT EXISTS questionnaire_responses (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        completed BOOLEAN DEFAULT false,
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        birth_date DATE,
        pronouns VARCHAR(50),
        main_goals TEXT[],
        challenges TEXT[],
        occupation VARCHAR(255),
        support_system VARCHAR(255),
        previous_therapy VARCHAR(255),
        coping_strategies TEXT[],
        communication_style VARCHAR(255),
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
        timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
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

    // Create indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_chat_sessions_user_id ON chat_sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_chat_sessions_start_time ON chat_sessions(start_time);
      CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id);
      CREATE INDEX IF NOT EXISTS idx_chat_messages_timestamp ON chat_messages(timestamp);
      CREATE INDEX IF NOT EXISTS idx_mood_entries_user_id ON mood_entries(user_id);
      CREATE INDEX IF NOT EXISTS idx_mood_entries_date ON mood_entries(entry_date);
      CREATE INDEX IF NOT EXISTS idx_journal_entries_user_id ON journal_entries(user_id);
      CREATE INDEX IF NOT EXISTS idx_journal_entries_date ON journal_entries(entry_date);
      CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires ON password_reset_tokens(expires_at);
    `);

    console.log('✅ Database tables initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
  }
}

// Initialize database on startup
initializeDatabase();

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

    // Create user profile
    await pool.query(
      `INSERT INTO user_profiles (user_id, name, first_name, last_name, pronouns, age, birth_date, join_date, profile_color_hex, notifications, biometric_auth, dark_mode, reminder_time) 
       VALUES ($1, $2, '', '', '', '', NULL, NOW(), '#800080', true, false, false, '19:00:00')`,
      [newUser.id, username]
    );

    // Create empty questionnaire response
    await pool.query(
      `INSERT INTO questionnaire_responses (user_id, completed, first_name, last_name, birth_date, pronouns, main_goals, challenges, occupation, support_system, previous_therapy, coping_strategies, communication_style) 
       VALUES ($1, false, '', '', NULL, '', '{}', '{}', '', '', '', '{}', '')`,
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

// CHAT ENDPOINT with PostgreSQL storage
app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    const { message, chatHistory, sessionId } = req.body;
    
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

    // Add current user message to session
    await pool.query(
      'INSERT INTO chat_messages (session_id, role, content, timestamp) VALUES ($1, $2, $3, NOW())',
      [currentSession.id, 'user', message]
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
        questionnaireContext += `\n- Name: ${responses.first_name} ${responses.last_name || ''} (call them ${responses.first_name})`;
      }
      if (responses.pronouns) {
        questionnaireContext += `\n- Pronouns: ${responses.pronouns}`;
      }
      if (responses.birth_date) {
        const age = Math.floor((new Date() - new Date(responses.birth_date)) / (365.25 * 24 * 60 * 60 * 1000));
        questionnaireContext += `\n- Age: ${age} years old`;
      }
      
      const goalsText = responses.main_goals && responses.main_goals.length > 0 
        ? responses.main_goals.join(', ') 
        : 'Not specified';
      
      questionnaireContext += `\n- Goals: ${goalsText}
- Challenges: ${responses.challenges ? responses.challenges.join(', ') : 'Not specified'}
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

// EXPORT TRAINING DATA
app.get('/api/export/training-data', authenticateToken, async (req, res) => {
  try {
    // Get user's questionnaire data
    const questionnaireResult = await pool.query(
      'SELECT * FROM questionnaire_responses WHERE user_id = $1',
      [req.user.userId]
    );

    // Get user's profile data
    const profileResult = await pool.query(
      'SELECT age, pronouns, join_date FROM user_profiles WHERE user_id = $1',
      [req.user.userId]
    );

    // Get conversations
    const conversationsResult = await pool.query(
      `SELECT 
        cs.id as session_id,
        cs.start_time,
        cs.last_activity,
        cs.user_context,
        json_agg(
          json_build_object(
            'role', cm.role,
            'content', cm.content,
            'timestamp', cm.timestamp
          ) ORDER BY cm.timestamp
        ) as messages
      FROM chat_sessions cs
      LEFT JOIN chat_messages cm ON cs.id = cm.session_id
      WHERE cs.user_id = $1
      GROUP BY cs.id, cs.start_time, cs.last_activity, cs.user_context
      ORDER BY cs.start_time`,
      [req.user.userId]
    );

    // Get mood patterns
    const moodResult = await pool.query(
      'SELECT mood, entry_date, (note IS NOT NULL) as has_note FROM mood_entries WHERE user_id = $1 ORDER BY entry_date',
      [req.user.userId]
    );

    // Get journal patterns
    const journalResult = await pool.query(
      'SELECT entry_date, (prompt IS NOT NULL) as has_prompt, LENGTH(content) as word_count FROM journal_entries WHERE user_id = $1 ORDER BY entry_date',
      [req.user.userId]
    );

    // Format data for AI training
    const trainingData = {
      userId: req.user.userId,
      exportDate: new Date().toISOString(),
      questionnaire: questionnaireResult.rows[0] || null,
      profile: profileResult.rows[0] || null,
      conversations: conversationsResult.rows.map(conv => ({
        sessionId: conv.session_id,
        startTime: conv.start_time,
        duration: conv.last_activity ? 
          new Date(conv.last_activity) - new Date(conv.start_time) : 0,
        messageCount: conv.messages ? conv.messages.length : 0,
        messages: conv.messages || [],
        userContext: conv.user_context
      })),
      moodPatterns: moodResult.rows,
      journalPatterns: journalResult.rows
    };

    res.json(trainingData);
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ error: 'Failed to export training data' });
  }
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
        completed: false, 
        responses: {
          firstName: "",
          lastName: "",
          birthDate: null,
          pronouns: "",
          mainGoals: [],
          challenges: [],
          occupation: "",
          supportSystem: "",
          previousTherapy: "",
          copingStrategies: [],
          communicationStyle: ""
        } 
      });
    }
    
    const questionnaire = questionnaireResult.rows[0];
    res.json({
      completed: questionnaire.completed,
      responses: {
        firstName: questionnaire.first_name || "",
        lastName: questionnaire.last_name || "",
        birthDate: questionnaire.birth_date,
        pronouns: questionnaire.pronouns || "",
        mainGoals: questionnaire.main_goals || [],
        challenges: questionnaire.challenges || [],
        occupation: questionnaire.occupation || "",
        supportSystem: questionnaire.support_system || "",
        previousTherapy: questionnaire.previous_therapy || "",
        copingStrategies: questionnaire.coping_strategies || [],
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

    const requiredFields = ['firstName', 'pronouns', 'mainGoals', 'challenges', 'occupation', 'supportSystem', 'copingStrategies', 'previousTherapy', 'communicationStyle'];
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

    // Update questionnaire responses
    await pool.query(
      `UPDATE questionnaire_responses 
       SET completed = true, 
           first_name = $1, 
           last_name = $2, 
           birth_date = $3, 
           pronouns = $4, 
           main_goals = $5, 
           challenges = $6, 
           occupation = $7, 
           support_system = $8, 
           previous_therapy = $9, 
           coping_strategies = $10, 
           communication_style = $11, 
           completed_at = NOW(),
           updated_at = NOW()
       WHERE user_id = $12`,
      [
        responses.firstName || "",
        responses.lastName || "",
        responses.birthDate || null,
        responses.pronouns || "",
        responses.mainGoals || [],
        responses.challenges || [],
        responses.occupation || "",
        responses.supportSystem || "",
        responses.previousTherapy || "",
        responses.copingStrategies || [],
        responses.communicationStyle || "",
        req.user.userId
      ]
    );

    // Update user profile with questionnaire data
    await pool.query(
      `UPDATE user_profiles 
       SET first_name = $1, 
           last_name = $2, 
           pronouns = $3, 
           birth_date = $4,
           name = $5,
           age = $6,
           updated_at = NOW()
       WHERE user_id = $7`,
      [
        responses.firstName || "",
        responses.lastName || "",
        responses.pronouns || "",
        responses.birthDate || null,
        `${responses.firstName || ""} ${responses.lastName || ""}`.trim(),
        responses.birthDate ? Math.floor((new Date() - new Date(responses.birthDate)) / (365.25 * 24 * 60 * 60 * 1000)).toString() : "",
        req.user.userId
      ]
    );
    
    console.log('✅ Questionnaire completed for user:', req.user.username);
    console.log('   Main goals selected:', responses.mainGoals);
    
    res.json({ success: true, message: 'Questionnaire completed successfully' });
  } catch (error) {
    console.error('Questionnaire save error:', error);
    res.status(500).json({ error: 'Failed to save questionnaire' });
  }
});

// PROFILE ENDPOINTS
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
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
      name: profile.name || "",
      firstName: profile.first_name || "",
      lastName: profile.last_name || "",
      pronouns: profile.pronouns || "",
      age: profile.age || "",
      birthDate: profile.birth_date,
      joinDate: profile.join_date,
      profileColorHex: profile.profile_color_hex || "#800080",
      notifications: profile.notifications,
      biometricAuth: profile.biometric_auth,
      darkMode: profile.dark_mode,
      reminderTime: profile.reminder_time
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
      name, 
      firstName,
      lastName,
      pronouns,
      age, 
      birthDate, 
      joinDate, 
      profileColorHex, 
      notifications, 
      biometricAuth, 
      darkMode, 
      reminderTime 
    } = req.body;
    
    await pool.query(
      `UPDATE user_profiles 
       SET name = COALESCE($1, name),
           first_name = COALESCE($2, first_name),
           last_name = COALESCE($3, last_name),
           pronouns = COALESCE($4, pronouns),
           age = COALESCE($5, age),
           birth_date = COALESCE($6, birth_date),
           join_date = COALESCE($7, join_date),
           profile_color_hex = COALESCE($8, profile_color_hex),
           notifications = COALESCE($9, notifications),
           biometric_auth = COALESCE($10, biometric_auth),
           dark_mode = COALESCE($11, dark_mode),
           reminder_time = COALESCE($12, reminder_time),
           updated_at = NOW()
       WHERE user_id = $13`,
      [
        name,
        firstName,
        lastName, 
        pronouns,
        age,
        birthDate,
        joinDate,
        profileColorHex,
        notifications,
        biometricAuth,
        darkMode,
        reminderTime,
        req.user.userId
      ]
    );
    
    console.log('✅ Profile updated for user:', req.user.username);
    
    res.json({ success: true, message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Profile save error:', error);
    res.status(500).json({ error: 'Failed to save profile' });
  }
});

// MOOD ENDPOINTS
app.get('/api/mood', authenticateToken, async (req, res) => {
  try {
    const moodResult = await pool.query(
      'SELECT id, mood, note, entry_date as date FROM mood_entries WHERE user_id = $1 ORDER BY entry_date DESC',
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
    const { id, mood, note, date } = req.body;
    
    if (!mood || !date) {
      return res.status(400).json({ error: 'Mood and date are required' });
    }
    
    if (mood < 1 || mood > 10) {
      return res.status(400).json({ error: 'Mood must be between 1 and 10' });
    }
    
    const moodResult = await pool.query(
      'INSERT INTO mood_entries (user_id, mood, note, entry_date) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.user.userId, parseInt(mood), note || null, date]
    );
    
    const savedEntry = moodResult.rows[0];
    
    res.json({ 
      success: true, 
      entry: {
        id: savedEntry.id,
        mood: savedEntry.mood,
        note: savedEntry.note,
        date: savedEntry.entry_date
      }
    });
  } catch (error) {
    console.error('Mood save error:', error);
    res.status(500).json({ error: 'Failed to save mood entry' });
  }
});

// JOURNAL ENDPOINTS
app.get('/api/journal', authenticateToken, async (req, res) => {
  try {
    const journalResult = await pool.query(
      'SELECT id, content, prompt, entry_date as date FROM journal_entries WHERE user_id = $1 ORDER BY entry_date DESC',
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
    const { id, content, prompt, date } = req.body;
    
    if (!content || !date) {
      return res.status(400).json({ error: 'Content and date are required' });
    }
    
    if (content.trim().length === 0) {
      return res.status(400).json({ error: 'Content cannot be empty' });
    }
    
    const journalResult = await pool.query(
      'INSERT INTO journal_entries (user_id, content, prompt, entry_date) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.user.userId, content.trim(), prompt || null, date]
    );
    
    const savedEntry = journalResult.rows[0];
    
    res.json({ 
      success: true, 
      entry: {
        id: savedEntry.id,
        content: savedEntry.content,
        prompt: savedEntry.prompt,
        date: savedEntry.entry_date
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
    // Delete all user data but keep the account
    await pool.query('DELETE FROM chat_messages WHERE session_id IN (SELECT id FROM chat_sessions WHERE user_id = $1)', [req.user.userId]);
    await pool.query('DELETE FROM chat_sessions WHERE user_id = $1', [req.user.userId]);
    await pool.query('DELETE FROM mood_entries WHERE user_id = $1', [req.user.userId]);
    await pool.query('DELETE FROM journal_entries WHERE user_id = $1', [req.user.userId]);
    
    // Reset questionnaire
    await pool.query(
      `UPDATE questionnaire_responses 
       SET completed = false, 
           first_name = '', 
           last_name = '', 
           birth_date = NULL, 
           pronouns = '', 
           main_goals = '{}', 
           challenges = '{}', 
           occupation = '', 
           support_system = '', 
           previous_therapy = '', 
           coping_strategies = '{}', 
           communication_style = '',
           completed_at = NULL,
           updated_at = NOW()
       WHERE user_id = $1`,
      [req.user.userId]
    );
    
    // Reset profile
    await pool.query(
      `UPDATE user_profiles 
       SET first_name = '', 
           last_name = '', 
           pronouns = '', 
           age = '', 
           birth_date = NULL,
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
    version: '3.0.0 - PostgreSQL Integration',
    database: 'PostgreSQL',
    endpoints: [
      '/api/auth/*', 
      '/api/questionnaire', 
      '/api/chat', 
      '/api/chat/sessions', 
      '/api/chat/sessions/:id',
      '/api/export/training-data',
      '/api/profile', 
      '/api/mood', 
      '/api/journal', 
      '/api/reset'
    ],
    features: [
      'Persistent PostgreSQL storage',
      'Chat session management with memory',
      'Complete user data persistence',
      'Training data export',
      'No more data loss on restart!'
    ]
  });
});

// Cleanup expired tokens periodically
setInterval(async () => {
  try {
    const result = await pool.query('DELETE FROM password_reset_tokens WHERE expires_at < NOW()');
    if (result.rowCount > 0) {
      console.log(`🧹 Cleaned up ${result.rowCount} expired password reset tokens`);
    }
  } catch (error) {
    console.error('Error cleaning up expired tokens:', error);
  }
}, 3600000); // 1 hour

app.listen(PORT, () => {
  console.log(`✅ Luma backend running on port ${PORT}`);
  console.log(`🌐 Server URL: https://luma-backend-nfdc.onrender.com`);
  console.log(`🗄️ Database: PostgreSQL with persistent storage`);
  console.log(`📧 Email service: ${process.env.RESEND_API_KEY ? '✅ Configured' : '❌ Missing RESEND_API_KEY'}`);
  console.log(`🤖 OpenAI service: ${process.env.OPENAI_API_KEY ? '✅ Configured' : '❌ Missing OPENAI_API_KEY'}`);
  console.log(`🔗 Database URL: ${process.env.DATABASE_URL ? '✅ Configured' : '❌ Missing DATABASE_URL'}`);
  console.log(`\n🎉 POSTGRESQL INTEGRATION:`);
  console.log(`   ✅ All data now persists permanently`);
  console.log(`   ✅ No more data loss on server restart`);
  console.log(`   ✅ Professional database with full SQL access`);
  console.log(`   ✅ Ready for production scaling`);
  console.log(`   ✅ Perfect for AI training data collection`);
  console.log(`\nAvailable endpoints:`);
  console.log(`- POST /api/auth/register`);
  console.log(`- POST /api/auth/login`);
  console.log(`- POST /api/auth/forgot-password`);
  console.log(`- POST /api/auth/reset-password`);
  console.log(`- GET /api/auth/me`);
  console.log(`- POST /api/auth/logout`);
  console.log(`- POST /api/chat (with persistent storage)`);
  console.log(`- GET /api/chat/sessions`);
  console.log(`- GET /api/chat/sessions/:id`);
  console.log(`- GET /api/export/training-data`);
  console.log(`- GET/POST /api/questionnaire`);
  console.log(`- GET/POST /api/profile`);
  console.log(`- GET/POST /api/mood`);
  console.log(`- GET/POST /api/journal`);
  console.log(`- POST /api/reset`);
});
