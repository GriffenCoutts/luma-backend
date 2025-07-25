const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

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
        max_tokens: 200
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

app.listen(PORT, () => {
  console.log(`✅ Luma backend running on port ${PORT}`);
});
