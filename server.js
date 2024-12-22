const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    credentials: true
}));
app.use(express.json());

// Modified MongoDB Schemas
const userSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: true, 
        unique: true 
    },
    password: { 
        type: String, 
        required: true 
    },
    isAdmin: { 
        type: Boolean, 
        default: false 
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    },
    // New fields for user preferences
    viewHistory: [{
        thoughtId: { type: mongoose.Schema.Types.ObjectId, ref: 'Thought' },
        timestamp: { type: Date, default: Date.now }
    }],
    tagPreferences: {
        type: Map,
        of: Number,
        default: {}
    }
});

const thoughtSchema = new mongoose.Schema({
    title: { 
        type: String,
        required: function() {
            return this.type === 'story' || this.type === 'poem';
        }
    },
    text: { 
        type: String, 
        required: true 
    },
    type: { 
        type: String, 
        required: true,
        enum: ['thought', 'poem', 'quote', 'story']
    },
    tags: [{
        type: String,
        required: true
    }],
    author: {
        type: String,
        required: true
    },
    date: { 
        type: String, 
        required: true 
    },
    views: { 
        type: Number, 
        default: 0 
    },
    reactions: { 
        type: Map, 
        of: [{
            userId: String,
            emoji: String
        }],
        default: {} 
    },
    timestamp: { 
        type: Number, 
        required: true 
    }
});

const User = mongoose.model('User', userSchema);
const Thought = mongoose.model('Thought', thoughtSchema);

// Auth Middleware
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'No auth token' });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Admin Middleware
const adminMiddleware = async (req, res, next) => {
    if (!req.user?.isAdmin) {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// Content Validation
const containsSpam = (text) => {
    // Check for URLs
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    if (urlRegex.test(text)) return true;

    // Check for email addresses
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    if (emailRegex.test(text)) return true;

    // Check for phone numbers
    const phoneRegex = /(\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}/g;
    if (phoneRegex.test(text)) return true;

    // Check for common spam phrases
    const spamPhrases = [
        'buy now', 'click here', 'free offer', 'limited time',
        'make money', 'winner', 'discount', 'subscribe'
    ];
    return spamPhrases.some(phrase => 
        text.toLowerCase().includes(phrase.toLowerCase())
    );
};

// Generate random nickname
const generateNickname = () => {
    const adjectives = ['Happy', 'Clever', 'Brave', 'Gentle', 'Kind', 'Swift'];
    const nouns = ['Panda', 'Fox', 'Eagle', 'Dolphin', 'Tiger', 'Owl'];
    return `${adjectives[Math.floor(Math.random() * adjectives.length)]}${nouns[Math.floor(Math.random() * nouns.length)]}${Math.floor(Math.random() * 1000)}`;
};

app.patch('/api/thoughts/:id/react', authMiddleware, async (req, res) => {
    try {
        const thought = await Thought.findById(req.params.id);
        if (!thought) {
            return res.status(404).json({ message: 'Thought not found' });
        }
        
        const { emoji } = req.body;
        const userId = req.user.id;
        
        if (!thought.reactions) {
            thought.reactions = new Map();
        }

        let reactions = thought.reactions.get(emoji) || [];
        const existingReaction = reactions.findIndex(r => r.userId === userId);

        if (existingReaction !== -1) {
            // Remove reaction if it exists
            reactions.splice(existingReaction, 1);
        } else {
            // Add new reaction
            reactions.push({ userId, emoji });
        }

        thought.reactions.set(emoji, reactions);
        await thought.save();
        
        res.json(thought);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});
// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, isAdmin } = req.body;
        
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
        
        // Generate token
        const token = jwt.sign(
            { id: user._id, username: user.username, isAdmin: user.isAdmin },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
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
