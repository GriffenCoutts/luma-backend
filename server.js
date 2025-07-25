const express = require('express');
const cors = require('cors');
require('dotenv').config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// In-memory storage (replace with database in production)
let userData = {
  profile: {
    name: "",
    age: "",
    birthDate: null,
    joinDate: new Date().toISOString(),
    profileColorHex: "800080", // Purple
    notifications: true,
    biometricAuth: false,
    darkMode: false,
    reminderTime: new Date().toISOString()
  },
  moodEntries: [],
  journalEntries: []
};

// EXISTING CHAT ENDPOINT (keeping your OpenAI integration)
app.post('/api/chat', async (req, res) => {
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
            content: `You are Luma, a brilliant and deeply empathetic friend who happens to have exceptional insight into human psychology. Talk like a real person, not a therapist bot. Be warm, genuine, and incredibly wise.`
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

// NEW PROFILE ENDPOINTS
app.get('/api/profile', (req, res) => {
  try {
    res.json(userData.profile);
  } catch (error) {
    console.error('Profile load error:', error);
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

app.post('/api/profile', (req, res) => {
  try {
    const { name, age, birthDate, joinDate, profileColorHex, notifications, biometricAuth, darkMode, reminderTime } = req.body;
    
    userData.profile = {
      name: name || userData.profile.name,
      age: age || userData.profile.age,
      birthDate: birthDate || userData.profile.birthDate,
      joinDate: joinDate || userData.profile.joinDate,
      profileColorHex: profileColorHex || userData.profile.profileColorHex,
      notifications: notifications !== undefined ? notifications : userData.profile.notifications,
      biometricAuth: biometricAuth !== undefined ? biometricAuth : userData.profile.biometricAuth,
      darkMode: darkMode !== undefined ? darkMode : userData.profile.darkMode,
      reminderTime: reminderTime || userData.profile.reminderTime
    };
    
    res.json({ success: true, profile: userData.profile });
  } catch (error) {
    console.error('Profile save error:', error);
    res.status(500).json({ error: 'Failed to save profile' });
  }
});

// NEW MOOD ENDPOINTS
app.get('/api/mood', (req, res) => {
  try {
    const sortedEntries = userData.moodEntries.sort((a, b) => new Date(b.date) - new Date(a.date));
    res.json(sortedEntries);
  } catch (error) {
    console.error('Mood load error:', error);
    res.status(500).json({ error: 'Failed to load mood entries' });
  }
});

app.post('/api/mood', (req, res) => {
  try {
    const { id, mood, note, date } = req.body;
    
    if (!mood || !date) {
      return res.status(400).json({ error: 'Mood and date are required' });
    }
    
    if (mood < 1 || mood > 10) {
      return res.status(400).json({ error: 'Mood must be between 1 and 10' });
    }
    
    const moodEntry = {
      id: id || generateUUID(),
      mood: parseInt(mood),
      note: note || null,
      date: date
    };
    
    userData.moodEntries.push(moodEntry);
    res.json({ success: true, entry: moodEntry });
  } catch (error) {
    console.error('Mood save error:', error);
    res.status(500).json({ error: 'Failed to save mood entry' });
  }
});

// NEW JOURNAL ENDPOINTS
app.get('/api/journal', (req, res) => {
  try {
    const sortedEntries = userData.journalEntries.sort((a, b) => new Date(b.date) - new Date(a.date));
    res.json(sortedEntries);
  } catch (error) {
    console.error('Journal load error:', error);
    res.status(500).json({ error: 'Failed to load journal entries' });
  }
});

app.post('/api/journal', (req, res) => {
  try {
    const { id, content, prompt, date } = req.body;
    
    if (!content || !date) {
      return res.status(400).json({ error: 'Content and date are required' });
    }
    
    if (content.trim().length === 0) {
      return res.status(400).json({ error: 'Content cannot be empty' });
    }
    
    const journalEntry = {
      id: id || generateUUID(),
      content: content.trim(),
      prompt: prompt || null,
      date: date
    };
    
    userData.journalEntries.push(journalEntry);
    res.json({ success: true, entry: journalEntry });
  } catch (error) {
    console.error('Journal save error:', error);
    res.status(500).json({ error: 'Failed to save journal entry' });
  }
});

// NEW RESET ENDPOINT
app.post('/api/reset', (req, res) => {
  try {
    userData = {
      profile: {
        name: "",
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
    
    res.json({ success: true, message: 'All data has been reset' });
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
    endpoints: ['/api/chat', '/api/profile', '/api/mood', '/api/journal', '/api/reset']
  });
});

app.listen(PORT, () => {
  console.log(`✅ Luma backend running on port ${PORT}`);
  console.log(`Available endpoints:`);
  console.log(`- POST /api/chat`);
  console.log(`- GET/POST /api/profile`);
  console.log(`- GET/POST /api/mood`);
  console.log(`- GET/POST /api/journal`);
  console.log(`- POST /api/reset`);
});
