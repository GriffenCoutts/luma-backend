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

    // Initialize user data
    userData[userId] = {
      profile: {
        name: username,
        age: "",
        birthDate: null,
        joinDate: new Date().toISOString(),
        profileColorHex: "800080",
        notifications: true,
        biometricAuth: false,
        darkMode: false,
        reminderTime: new Date().toISOString()
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

// FORGOT PASSWORD - Request Reset
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Find user by email
    const user = users.find(u => u.email === email);
    if (!user) {
      // Don't reveal if email exists or not for security
      return res.json({ 
        success: true, 
        message: 'If an account with that email exists, we have sent a password reset link.' 
      });
    }

    // Generate reset token
    const resetToken = generateUUID();
    const expires = new Date(Date.now() + 3600000); // 1 hour from now

    // Store reset token
    passwordResetTokens[resetToken] = {
      userId: user.id,
      expires: expires
    };

    // Send email
    try {
      await resend.emails.send({
        from: 'Luma <noreply@yourdomain.com>', // Replace with your domain
        to: [email],
        subject: 'Reset Your Luma Password',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #7C3AED;">Reset Your Luma Password</h2>
            <p>Hi ${user.username},</p>
            <p>We received a request to reset your password. Click the link below to create a new password:</p>
            <a href="luma://reset-password?token=${resetToken}" 
               style="background-color: #7C3AED; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 20px 0;">
              Reset Password
            </a>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this, you can safely ignore this email.</p>
            <p>Best regards,<br>The Luma Team</p>
          </div>
        `
      });

      res.json({ 
        success: true, 
        message: 'Password reset email sent successfully.' 
      });

    } catch (emailError) {
      console.error('Email sending error:', emailError);
      res.status(500).json({ error: 'Failed to send reset email' });
    }

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// RESET PASSWORD - Confirm Reset
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if token exists and is valid
    const resetData = passwordResetTokens[token];
    if (!resetData) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    // Check if token is expired
    if (new Date() > resetData.expires) {
      delete passwordResetTokens[token];
      return res.status(400).json({ error: 'Reset token has expired' });
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
    delete passwordResetTokens[token];

    res.json({
      success: true,
      message: 'Password reset successfully'
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Server error' });
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

// UPDATED CHAT ENDPOINT (with authentication)
app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;
    
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-4',
        messages: [
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

Be warm, genuine, and focus on evidence-based mental health practices. Keep responses helpful, engaging, and grounded in psychological wellness principles.`
          },
          {
            role: 'user',
            content: message
          }
        ],
        temperature: 0.9,
        max_tokens: 500
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

// UPDATED PROFILE ENDPOINTS (with authentication)
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
    const { name, age, birthDate, joinDate, profileColorHex, notifications, biometricAuth, darkMode, reminderTime } = req.body;
    
    if (!userData[req.user.userId]) {
      userData[req.user.userId] = { profile: {}, moodEntries: [], journalEntries: [] };
    }

    const currentProfile = userData[req.user.userId].profile;
    
    userData[req.user.userId].profile = {
      name: name || currentProfile.name,
      age: age || currentProfile.age,
      birthDate: birthDate || currentProfile.birthDate,
      joinDate: joinDate || currentProfile.joinDate,
      profileColorHex: profileColorHex || currentProfile.profileColorHex,
      notifications: notifications !== undefined ? notifications : currentProfile.notifications,
      biometricAuth: biometricAuth !== undefined ? biometricAuth : currentProfile.biometricAuth,
      darkMode: darkMode !== undefined ? darkMode : currentProfile.darkMode,
      reminderTime: reminderTime || currentProfile.reminderTime
    };
    
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
      userData[req.user.userId] = { profile: {}, moodEntries: [], journalEntries: [] };
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
      userData[req.user.userId] = { profile: {}, moodEntries: [], journalEntries: [] };
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
        age: "",
        birthDate: null,
        joinDate: new Date().toISOString(),
        profileColorHex: "800080",
        notifications: true,
        biometricAuth: false,
        darkMode: false,
        reminderTime: new Date().toISOString()
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
    endpoints: ['/api/auth/*', '/api/chat', '/api/profile', '/api/mood', '/api/journal', '/api/reset']
  });
});

// Cleanup expired tokens every hour
setInterval(() => {
  const now = new Date();
  Object.keys(passwordResetTokens).forEach(token => {
    if (now > passwordResetTokens[token].expires) {
      delete passwordResetTokens[token];
    }
  });
}, 3600000); // 1 hour

app.listen(PORT, () => {
  console.log(`✅ Luma backend running on port ${PORT}`);
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
