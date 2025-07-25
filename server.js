// UPDATED CHAT ENDPOINT (mental health focus only)
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
