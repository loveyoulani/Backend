const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

app.use(limiter);
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    credentials: true
}));
app.use(express.json());

// Enhanced spam detection system
const spamDetection = {
    // Patterns for detecting repetitive characters
    repetitivePattern: /(.)\1{4,}/,  // Matches 5 or more of the same character
    
    // Pattern for excessive caps
    excessiveCaps: /[A-Z]{5,}/,
    
    // Common spam phrases - expanded list
    spamPhrases: [
        'buy now', 'click here', 'free offer', 'limited time',
        'make money', 'winner', 'discount', 'subscribe',
        'order now', 'act now', 'call now', 'apply now',
        'prescription', 'medication', 'casino', 'loan',
        'investment', 'bitcoin', 'crypto', 'lottery',
        'warranty', 'free money', 'work from home'
    ],

    // URLs and contact information patterns
    urlPattern: /(https?:\/\/[^\s]+)/g,
    emailPattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    phonePattern: /(\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}/g,
    
    // Character ratio checks
    getCharacterRatios(text) {
        const total = text.length;
        if (total === 0) return { caps: 0, special: 0 };
        
        const caps = (text.match(/[A-Z]/g) || []).length / total;
        const special = (text.match(/[^a-zA-Z0-9\s]/g) || []).length / total;
        
        return { caps, special };
    },
    
    // Entropy calculation for randomness detection
    calculateEntropy(text) {
        const freq = {};
        for (let char of text) {
            freq[char] = (freq[char] || 0) + 1;
        }
        
        return Object.values(freq).reduce((entropy, count) => {
            const p = count / text.length;
            return entropy - (p * Math.log2(p));
        }, 0);
    },

    // Main spam detection function
    containsSpam(text, isComment = false) {
        // Skip empty content
        if (!text || text.trim().length === 0) return false;
        
        // Allow common internet expressions and emoticons
        const allowedPatterns = [
            /x+d+/i,  // Matches xd, xdd, etc.
            /l+o+l+/i,  // Matches lol, loool, etc.
            /h+a+h+a+/i,  // Matches haha, hahaha, etc.
            /:\)|:\(|:D|:P|XD|<3/  // Common emoticons
        ];
        
        // Remove allowed patterns temporarily for spam checking
        let sanitizedText = text;
        allowedPatterns.forEach(pattern => {
            sanitizedText = sanitizedText.replace(pattern, '');
        });
        
        // Get character ratios
        const ratios = this.getCharacterRatios(sanitizedText);
        const entropy = this.calculateEntropy(sanitizedText);
        
        // Spam detection rules
        const isSpam = (
            // Check for repetitive patterns (unless it's an allowed pattern)
            this.repetitivePattern.test(sanitizedText) ||
            
            // Check for excessive caps (more than 50% caps)
            ratios.caps > 0.5 ||
            
            // Check for excessive special characters (more than 30%)
            ratios.special > 0.3 ||
            
            // Check for very low entropy (indicating repetitive content)
            entropy < 2.0 ||
            
            // Check for spam phrases
            this.spamPhrases.some(phrase => 
                sanitizedText.toLowerCase().includes(phrase.toLowerCase())
            ) ||
            
            // Check for URLs, emails, and phone numbers (if not allowed)
            (!isComment && (
                this.urlPattern.test(sanitizedText) ||
                this.emailPattern.test(sanitizedText) ||
                this.phonePattern.test(sanitizedText)
            ))
        );
        
        return isSpam;
    }
};

// Update the thought creation route with enhanced spam detection
app.post('/api/thoughts', authMiddleware, async (req, res) => {
    try {
        const { title, text, type } = req.body;
        
        // Enhanced spam detection
        if (title && spamDetection.containsSpam(title)) {
            return res.status(400).json({ message: 'Title contains spam or inappropriate content' });
        }
        if (spamDetection.containsSpam(text)) {
            return res.status(400).json({ message: 'Content contains spam or inappropriate content' });
        }
        
        // Create thought with author
        const thought = new Thought({
            ...req.body,
            author: req.body.author || generateNickname(),
            timestamp: Date.now()
        });
        
        const newThought = await thought.save();
        res.status(201).json(newThought);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Password validation middleware
const validatePassword = (password) => {
    const minLength = 8;
    const hasNumber = /\d/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    return (
        password.length >= minLength &&
        hasNumber &&
        hasUpper &&
        hasLower &&
        hasSpecial
    );
};

// Update auth routes with password validation
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, isAdmin } = req.body;
        
        // Validate password
        if (!validatePassword(password)) {
            return res.status(400).json({
                message: 'Password must be at least 8 characters and contain uppercase, lowercase, number, and special character'
            });
        }
        
        // Check if user exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const user = new User({
            username,
            password: hashedPassword,
            isAdmin: isAdmin && process.env.ADMIN_SECRET === req.body.adminSecret
        });
        
        await user.save();
        
        // Generate token with environment-based expiration
        const token = jwt.sign(
            { id: user._id, username: user.username, isAdmin: user.isAdmin },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRATION || '24h' }
        );
        
        res.status(201).json({ token });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Find user
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        // Generate token
        const token = jwt.sign(
            { id: user._id, username: user.username, isAdmin: user.isAdmin },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Thought Routes
app.get('/api/thoughts', async (req, res) => {
    try {
        const thoughts = await Thought.find().sort({ timestamp: -1 });
        res.json(thoughts);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/thoughts', authMiddleware, async (req, res) => {
    try {
        const { title, text, type } = req.body;
        
        // Spam detection
        if (containsSpam(title) || containsSpam(text)) {
            return res.status(400).json({ message: 'Content contains spam or inappropriate content' });
        }
        
        // Create thought with author
        const thought = new Thought({
            ...req.body,
            author: req.body.author || generateNickname(),
            timestamp: Date.now()
        });
        
        const newThought = await thought.save();
        res.status(201).json(newThought);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

app.patch('/api/thoughts/:id/view', authMiddleware, async (req, res) => {
    try {
        const thought = await Thought.findById(req.params.id);
        if (!thought) {
            return res.status(404).json({ message: 'Thought not found' });
        }
        
        thought.views = (thought.views || 0) + 1;
        await thought.save();

        // Update user's view history and tag preferences
        const user = await User.findById(req.user.id);
        if (user) {
            // Update view history
            user.viewHistory.push({
                thoughtId: thought._id,
                timestamp: new Date()
            });

            // Update tag preferences
            thought.tags.forEach(tag => {
                const currentWeight = user.tagPreferences.get(tag) || 0;
                user.tagPreferences.set(tag, currentWeight + 1);
            });

            await user.save();
        }

        res.json(thought);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});


app.patch('/api/thoughts/:id/react', authMiddleware, async (req, res) => {
    try {
        const thought = await Thought.findById(req.params.id);
        if (!thought) {
            return res.status(404).json({ message: 'Thought not found' });
        }
        
        const { emoji } = req.body;
        
        if (!thought.reactions) {
            thought.reactions = new Map();
        }
        
        thought.reactions.set(emoji, (thought.reactions.get(emoji) || 0) + 1);
        await thought.save();
        res.json(thought);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Admin Routes
app.delete('/api/thoughts/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const thought = await Thought.findByIdAndDelete(req.params.id);
        if (!thought) {
            return res.status(404).json({ message: 'Thought not found' });
        }
        res.json({ message: 'Thought deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/admin/dashboard', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const stats = {
            totalThoughts: await Thought.countDocuments(),
            totalUsers: await User.countDocuments(),
            recentThoughts: await Thought.find().sort({ timestamp: -1 }).limit(10)
        };
        res.json(stats);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});
app.get('/api/thoughts/recommended', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Get user's tag preferences
        const tagPreferences = user.tagPreferences || new Map();
        
        // Get recent thoughts
        const thoughts = await Thought.find().sort({ timestamp: -1 });
        
        // Score each thought based on user preferences
        const scoredThoughts = thoughts.map(thought => {
            let score = 0;
            thought.tags.forEach(tag => {
                score += tagPreferences.get(tag) || 0;
            });
            return { thought, score };
        });

        // Sort by score and return top results
        const recommended = scoredThoughts
            .sort((a, b) => b.score - a.score)
            .map(item => item.thought);

        res.json(recommended);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ message: 'Route not found' });
});

const PORT = process.env.PORT || 3000;

// Connect to MongoDB and start server
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('Connected to MongoDB');
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    })
    .catch((error) => {
        console.error('Could not connect to MongoDB:', error);
    });

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    mongoose.connection.close(false, () => {
        console.log('MongoDB connection closed.');
        process.exit(0);
    });
});
module.exports = app;
