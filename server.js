const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Resend } = require('resend');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Initialize Resend
const resend = new Resend(process.env.RESEND_API_KEY);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this';

// In-memory storage (replace with database in production)
let users = []; // { id, username, email, password, createdAt }
let userData = {}; // { userId: { profile: {}, moodEntries: [], journalEntries: [] } }
let passwordResetTokens = {}; // { token: { userId, expires } }

// AUTHENTICATION MIDDLEWARE
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

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

    // Basic validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }

    // Check if user already exists
    const existingUser = users.find(u => u.username === username || u.email === email);
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const userId = generateUUID();
    const newUser = {
      id: userId,
      username,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);

    // Initialize user data with NEW FIELDS
    userData[userId] = {
      profile: {
        name: username,
        firstName: "",        // NEW
        lastName: "",         // NEW
        pronouns: "",         // NEW
        age: "",
        birthDate: null,
        joinDate: new Date().toISOString(),
        profileColorHex: "800080",
        notifications: true,
        biometricAuth: false,
        darkMode: false,
        reminderTime: new Date().toISOString()
      },
      questionnaire: {
        completed: false,
        responses: {
          firstName: "",              // NEW
          lastName: "",               // NEW
          birthDate: null,            // NEW
          pronouns: "",               // NEW
          mainGoal: "",
          challenges: [],
          ageRange: "",
          occupation: "",
          supportSystem: "",
          previousTherapy: "",
          copingStrategies: [],
          communicationStyle: ""
        }
      },
      moodEntries: [],
      journalEntries: []
    };

    // Generate JWT token
    const token = jwt.sign(
      { userId: userId, username: username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'User registered successfully',
      token,
      user: {
        id: userId,
        username,
        email
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
    const user = users.find(u => u.username === username || u.email === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
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

// FORGOT PASSWORD - Request Reset (FULLY FIXED)
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    console.log('🔍 Password reset request for:', email);
    console.log('🔑 RESEND_API_KEY exists:', !!process.env.RESEND_API_KEY);

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Find user by email
    const user = users.find(u => u.email === email);
    console.log('👤 User found:', !!user);

    if (!user) {
      // Don't reveal if email exists or not for security
      return res.json({ 
        success: true, 
        message: 'If an account with that email exists, we have sent a password reset code.' 
      });
    }

    // Generate reset token (shorter, more user-friendly)
    const resetToken = Math.random().toString(36).substring(2, 8).toUpperCase();
    const expires = new Date(Date.now() + 3600000); // 1 hour from now

    // Store reset token
    passwordResetTokens[resetToken] = {
      userId: user.id,
      expires: expires
    };

    console.log('🎫 Generated reset token:', resetToken);

    // Send email with Resend's default domain
    try {
      console.log('📧 Attempting to send email to:', email);
      
      const emailResult = await resend.emails.send({
        from: 'onboarding@resend.dev', // FIXED: Using Resend's default domain
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

      console.log('✅ Email sent successfully. Result:', emailResult);

      res.json({ 
        success: true, 
        message: 'Password reset code sent to your email. Please check your inbox!' 
      });

    } catch (emailError) {
      console.error('❌ Email sending failed:', emailError);
      console.error('📋 Full error details:', JSON.stringify(emailError, null, 2));
      
      res.status(500).json({ 
        error: 'Failed to send reset email. Please try again or contact support.',
        details: process.env.NODE_ENV === 'development' ? emailError.message : undefined
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

    console.log('🔄 Password reset attempt with token:', token);

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Reset code and new password are required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    // Check if token exists and is valid (case insensitive)
    const resetData = passwordResetTokens[token.toUpperCase()];
    if (!resetData) {
      console.log('❌ Invalid token:', token);
      return res.status(400).json({ error: 'Invalid or expired reset code. Please request a new one.' });
    }

    // Check if token is expired
    if (new Date() > resetData.expires) {
      delete passwordResetTokens[token.toUpperCase()];
      console.log('⏰ Token expired:', token);
      return res.status(400).json({ error: 'Reset code has expired. Please request a new one.' });
    }

    // Find user
    const user = users.find(u => u.id === resetData.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Hash new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update user password
    user.password = hashedPassword;

    // Remove used token
    delete passwordResetTokens[token.toUpperCase()];

    console.log('✅ Password reset successful for user:', user.username);

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
app.get('/api/auth/me', authenticateToken, (req, res) => {
  try {
    const user = users.find(u => u.id === req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      createdAt: user.createdAt
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// LOGOUT (Optional - mainly for clearing client-side token)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

// IMPROVED CHAT ENDPOINT (with better conversational AI and name/pronouns context)
app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    const { message, chatHistory } = req.body;
    
    // Get user's questionnaire responses for context
    const userQuestionnaire = userData[req.user.userId]?.questionnaire;
    const userProfile = userData[req.user.userId]?.profile;
    let questionnaireContext = '';
    
    if (userQuestionnaire && userQuestionnaire.completed && userQuestionnaire.responses) {
      const responses = userQuestionnaire.responses;
      questionnaireContext = `\n\nIMPORTANT USER CONTEXT (reference naturally when relevant):`;
      
      // NEW: Add personal information
      if (responses.firstName) {
        questionnaireContext += `\n- Name: ${responses.firstName} ${responses.lastName || ''} (call them ${responses.firstName})`;
      }
      if (responses.pronouns) {
        questionnaireContext += `\n- Pronouns: ${responses.pronouns} (use these when referring to them)`;
      }
      if (responses.birthDate) {
        const age = Math.floor((new Date() - new Date(responses.birthDate)) / (365.25 * 24 * 60 * 60 * 1000));
        questionnaireContext += `\n- Age: ${age} years old`;
      }
      
      questionnaireContext += `\n- What brings them to Luma: ${responses.mainGoal || 'Not specified'}
- Current challenges: ${responses.challenges ? responses.challenges.join(', ') : 'Not specified'}
- Age range: ${responses.ageRange || 'Not specified'}
- Occupation: ${responses.occupation || 'Not specified'}
- Support system: ${responses.supportSystem || 'Not specified'}
- Previous therapy/counseling: ${responses.previousTherapy || 'Not specified'}
- Preferred coping strategies: ${responses.copingStrategies ? responses.copingStrategies.join(', ') : 'Not specified'}
- Communication preference: ${responses.communicationStyle || 'Not specified'}

Use this information to personalize your responses and reference relevant details when appropriate, but don't dump it all at once.`;
    }
    
    // Build the conversation history for OpenAI
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

EXAMPLES OF GOOD RESPONSES:

User: "Everyone is busy, I only have you to talk to"
Good: "That sounds really isolating and lonely. It's hard when it feels like everyone around you is caught up in their own world and you're left feeling disconnected. What's been going on that's making you feel this way? Is this something recent, or has it been building up over time?"

User: "I'm stressed about work"
Good: "Work stress can really weigh on you and affect everything else. What's happening at work that's got you feeling this way? Is it your workload, a particular project, or maybe something with colleagues or your boss?"

User: "I can't sleep"
Good: "Sleep troubles are so frustrating - lying there while your mind just won't quiet down. How long has this been going on? What's usually running through your head when you're trying to fall asleep?"

TONE: Warm, genuine, curious, supportive - like talking to someone who really cares about understanding your experience first, not just solving your problems.

IMPORTANT - AVOID:
- Numbered lists of suggestions (1) 2) 3))
- Immediately jumping to solutions before understanding
- Generic advice without knowing their specific context
- Sounding clinical, robotic, or overly therapeutic
- Giving multiple strategies at once

Remember: People want to feel heard and understood FIRST, then gently guided toward insights. Focus on building emotional connection through genuine curiosity and empathy.${questionnaireContext}`
      }
    ];
    
    // Add conversation history if provided
    if (chatHistory && Array.isArray(chatHistory)) {
      // Convert chat history to OpenAI format
      chatHistory.forEach(msg => {
        messages.push({
          role: msg.isUser ? 'user' : 'assistant',
          content: msg.text
        });
      });
    }
    
    // Add the current message
    messages.push({
      role: 'user',
      content: message
    });
    
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
      res.json({ 
        response: data.choices[0].message.content,
        success: true 
      });
    } else {
      res.status(500).json({ 
        error: 'No response from AI',
        success: false 
      });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ 
      error: 'Server error',
      success: false 
    });
  }
});

// QUESTIONNAIRE ENDPOINTS
app.get('/api/questionnaire', authenticateToken, (req, res) => {
  try {
    const userQuestionnaire = userData[req.user.userId]?.questionnaire;
    if (!userQuestionnaire) {
      return res.json({ completed: false, responses: {} });
    }
    res.json(userQuestionnaire);
  } catch (error) {
    console.error('Questionnaire load error:', error);
    res.status(500).json({ error: 'Failed to load questionnaire' });
  }
});

app.post('/api/questionnaire', authenticateToken, (req, res) => {
  try {
    const { responses } = req.body;
    
    if (!responses || typeof responses !== 'object') {
      return res.status(400).json({ error: 'Invalid questionnaire responses' });
    }

    if (!userData[req.user.userId]) {
      userData[req.user.userId] = { 
        profile: {
          name: "",
          firstName: "",
          lastName: "",
          pronouns: "",
          age: "",
          birthDate: null,
          joinDate: new Date().toISOString(),
          profileColorHex: "800080",
          notifications: true,
          biometricAuth: false,
          darkMode: false,
          reminderTime: new Date().toISOString()
        }, 
        questionnaire: {}, 
        moodEntries: [], 
        journalEntries: [] 
      };
    }
    
    userData[req.user.userId].questionnaire = {
      completed: true,
      responses: responses,
      completedAt: new Date().toISOString()
    };
    
    res.json({ success: true, questionnaire: userData[req.user.userId].questionnaire });
  } catch (error) {
    console.error('Questionnaire save error:', error);
    res.status(500).json({ error: 'Failed to save questionnaire' });
  }
});

// UPDATED PROFILE ENDPOINTS (with authentication and new fields)
app.get('/api/profile', authenticateToken, (req, res) => {
  try {
    const userProfile = userData[req.user.userId]?.profile;
    if (!userProfile) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    res.json(userProfile);
  } catch (error) {
    console.error('Profile load error:', error);
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

app.post('/api/profile', authenticateToken, (req, res) => {
  try {
    const { 
      name, 
      firstName,        // NEW
      lastName,         // NEW
      pronouns,         // NEW
      age, 
      birthDate, 
      joinDate, 
      profileColorHex, 
      notifications, 
      biometricAuth, 
      darkMode, 
      reminderTime 
    } = req.body;
    
    if (!userData[req.user.userId]) {
      userData[req.user.userId] = { 
        profile: {}, 
        questionnaire: {
          completed: false,
          responses: {}
        },
        moodEntries: [], 
        journalEntries: [] 
      };
    }

    const currentProfile = userData[req.user.userId].profile;
    
    userData[req.user.userId].profile = {
      name: name || currentProfile.name,
      firstName: firstName || currentProfile.firstName || "",           // NEW
      lastName: lastName || currentProfile.lastName || "",              // NEW
      pronouns: pronouns || currentProfile.pronouns || "",              // NEW
      age: age || currentProfile.age,
      birthDate: birthDate || currentProfile.birthDate,
      joinDate: joinDate || currentProfile.joinDate,
      profileColorHex: profileColorHex || currentProfile.profileColorHex,
      notifications: notifications !== undefined ? notifications : currentProfile.notifications,
      biometricAuth: biometricAuth !== undefined ? biometricAuth : currentProfile.biometricAuth,
      darkMode: darkMode !== undefined ? darkMode : currentProfile.darkMode,
      reminderTime: reminderTime || currentProfile.reminderTime
    };
    
    console.log('✅ Profile updated for user:', req.user.username);
    console.log('   New profile data:', userData[req.user.userId].profile);
    
    res.json({ success: true, profile: userData[req.user.userId].profile });
  } catch (error) {
    console.error('Profile save error:', error);
    res.status(500).json({ error: 'Failed to save profile' });
  }
});

// UPDATED MOOD ENDPOINTS (with authentication)
app.get('/api/mood', authenticateToken, (req, res) => {
  try {
    const userMoodEntries = userData[req.user.userId]?.moodEntries || [];
    const sortedEntries = userMoodEntries.sort((a, b) => new Date(b.date) - new Date(a.date));
    res.json(sortedEntries);
  } catch (error) {
    console.error('Mood load error:', error);
    res.status(500).json({ error: 'Failed to load mood entries' });
  }
});

app.post('/api/mood', authenticateToken, (req, res) => {
  try {
    const { id, mood, note, date } = req.body;
    
    if (!mood || !date) {
      return res.status(400).json({ error: 'Mood and date are required' });
    }
    
    if (mood < 1 || mood > 10) {
      return res.status(400).json({ error: 'Mood must be between 1 and 10' });
    }

    if (!userData[req.user.userId]) {
      userData[req.user.userId] = { profile: {}, questionnaire: {}, moodEntries: [], journalEntries: [] };
    }
    
    const moodEntry = {
      id: id || generateUUID(),
      mood: parseInt(mood),
      note: note || null,
      date: date
    };
    
    userData[req.user.userId].moodEntries.push(moodEntry);
    res.json({ success: true, entry: moodEntry });
  } catch (error) {
    console.error('Mood save error:', error);
    res.status(500).json({ error: 'Failed to save mood entry' });
  }
});

// UPDATED JOURNAL ENDPOINTS (with authentication)
app.get('/api/journal', authenticateToken, (req, res) => {
  try {
    const userJournalEntries = userData[req.user.userId]?.journalEntries || [];
    const sortedEntries = userJournalEntries.sort((a, b) => new Date(b.date) - new Date(a.date));
    res.json(sortedEntries);
  } catch (error) {
    console.error('Journal load error:', error);
    res.status(500).json({ error: 'Failed to load journal entries' });
  }
});

app.post('/api/journal', authenticateToken, (req, res) => {
  try {
    const { id, content, prompt, date } = req.body;
    
    if (!content || !date) {
      return res.status(400).json({ error: 'Content and date are required' });
    }
    
    if (content.trim().length === 0) {
      return res.status(400).json({ error: 'Content cannot be empty' });
    }

    if (!userData[req.user.userId]) {
      userData[req.user.userId] = { profile: {}, questionnaire: {}, moodEntries: [], journalEntries: [] };
    }
    
    const journalEntry = {
      id: id || generateUUID(),
      content: content.trim(),
      prompt: prompt || null,
      date: date
    };
    
    userData[req.user.userId].journalEntries.push(journalEntry);
    res.json({ success: true, entry: journalEntry });
  } catch (error) {
    console.error('Journal save error:', error);
    res.status(500).json({ error: 'Failed to save journal entry' });
  }
});

// RESET USER DATA (authenticated user only)
app.post('/api/reset', authenticateToken, (req, res) => {
  try {
    userData[req.user.userId] = {
      profile: {
        name: req.user.username,
        firstName: "",
        lastName: "",
        pronouns: "",
        age: "",
        birthDate: null,
        joinDate: new Date().toISOString(),
        profileColorHex: "800080",
        notifications: true,
        biometricAuth: false,
        darkMode: false,
        reminderTime: new Date().toISOString()
      },
      questionnaire: {
        completed: false,
        responses: {}
      },
      moodEntries: [],
      journalEntries: []
    };
    
    res.json({ success: true, message: 'Your data has been reset' });
  } catch (error) {
    console.error('Reset error:', error);
    res.status(500).json({ error: 'Failed to reset data' });
  }
});

// UTILITY FUNCTION
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// HEALTH CHECK
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    endpoints: ['/api/auth/*', '/api/questionnaire', '/api/chat', '/api/profile', '/api/mood', '/api/journal', '/api/reset']
  });
});

// Cleanup expired tokens every hour
setInterval(() => {
  const now = new Date();
  Object.keys(passwordResetTokens).forEach(token => {
    if (now > passwordResetTokens[token].expires) {
      delete passwordResetTokens[token];
      console.log('🧹 Cleaned up expired token:', token);
    }
  });
}, 3600000); // 1 hour

app.listen(PORT, () => {
  console.log(`✅ Luma backend running on port ${PORT}`);
  console.log(`🌐 Server URL: https://luma-backend-nfdc.onrender.com`);
  console.log(`📧 Email service: ${process.env.RESEND_API_KEY ? '✅ Configured' : '❌ Missing RESEND_API_KEY'}`);
  console.log(`🤖 OpenAI service: ${process.env.OPENAI_API_KEY ? '✅ Configured' : '❌ Missing OPENAI_API_KEY'}`);
  console.log(`Available endpoints:`);
  console.log(`- POST /api/auth/register`);
  console.log(`- POST /api/auth/login`);
  console.log(`- POST /api/auth/forgot-password`);
  console.log(`- POST /api/auth/reset-password`);
  console.log(`- GET /api/auth/me`);
  console.log(`- POST /api/auth/logout`);
  console.log(`- POST /api/chat (authenticated)`);
  console.log(`- GET/POST /api/profile (authenticated)`);
  console.log(`- GET/POST /api/mood (authenticated)`);
  console.log(`- GET/POST /api/journal (authenticated)`);
  console.log(`- POST /api/reset (authenticated)`);
});
