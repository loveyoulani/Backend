const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const https = require('https');
require('dotenv').config();

const app = express();

const PING_INTERVAL = 14 * 60 * 1000;

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
    lastPostTime: {
        type: Date,
        default: null
    },
    postCount: {
        type: Number,
        default: 0
    },
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
        },
        maxlength: 200
    },
    text: { 
        type: String, 
        required: true,
        maxlength: 10000
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

const PING_INTERVAL = 14 * 60 * 1000; // 14 minutes
const pingServer = () => {
    const options = {
        hostname: process.env.APP_URL || 'your-app-name.onrender.com', // Replace with your actual Render URL
        path: '/api/ping',
        method: 'GET'
    };

    const req = https.request(options, (res) => {
        console.log(`Ping status: ${res.statusCode}`);
    });

    req.on('error', (error) => {
        console.error('Error pinging server:', error);
    });

    req.end();
};

// Add ping endpoint
app.get('/api/ping', (req, res) => {
    res.status(200).send('pong');
});

// Start ping interval after server starts
let pingInterval;

// Enhanced Content Validation
const contentValidation = {
    // Check for spam patterns
    containsSpam: (text) => {
        if (!text) return false;
        
        // Convert to lowercase for case-insensitive checks
        const lowerText = text.toLowerCase();
        
        // Check for URLs
        const urlRegex = /(https?:\/\/[^\s]+)/g;
        if (urlRegex.test(text)) return true;

        // Check for email addresses
        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        if (emailRegex.test(text)) return true;

        // Check for phone numbers
        const phoneRegex = /(\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}/g;
        if (phoneRegex.test(text)) return true;

        // Check for excessive capitalization (more than 70% caps)
        const capsPercentage = (text.match(/[A-Z]/g) || []).length / text.length;
        if (text.length > 10 && capsPercentage > 0.7) return true;

        // Check for character repetition (like 'aaaaaa' or '!!!!!!!')
        if (/(.)\1{7,}/g.test(text)) return true;

        // Check for keyboard smashing patterns
        if (/[qwfpgjluy]{8,}|[asdheio]{8,}|[zxcvbnm]{8,}/gi.test(text)) return true;

        // Check for excessive punctuation
        if (/[!?.,]{4,}/g.test(text)) return true;

        // Check for common spam phrases
        const spamPhrases = [
            'buy now', 'click here', 'free offer', 'limited time',
            'make money', 'winner', 'discount', 'subscribe', 'win win',
            'guarantee', 'double your', 'earn extra', 'extra cash',
            'free money', 'best price', 'special offer', 'act now',
            'amazing', 'congratulations', 'credit card', 'free access',
            'free consultation', 'free gift', 'free hosting', 'free info',
            'free investment', 'free membership', 'free money', 'free preview',
            'free quote', 'free trial', 'free website', 'hidden charges',
            'hot stuff', 'incredible deal', 'info you requested',
            'interesting proposal', 'limited time', 'new customers only',
            'offer expires', 'only $', 'order now', 'please read',
            'satisfaction guaranteed', 'save $', 'save big money',
            'save up to', 'special promotion'
        ];

        return spamPhrases.some(phrase => lowerText.includes(phrase));
    },

    // Check for gibberish text
    isGibberish: (text) => {
        if (!text) return false;

        // Calculate entropy (randomness) of the text
        const calculateEntropy = (str) => {
            const len = str.length;
            const frequencies = Array.from(str).reduce((freq, c) => {
                freq[c] = (freq[c] || 0) + 1;
                return freq;
            }, {});
            
            return Object.values(frequencies).reduce((entropy, f) => {
                const p = f / len;
                return entropy - (p * Math.log2(p));
            }, 0);
        };

        // Check consonant-to-vowel ratio
        const consonantVowelRatio = (str) => {
            const vowels = str.toLowerCase().match(/[aeiou]/g) || [];
            const consonants = str.toLowerCase().match(/[bcdfghjklmnpqrstvwxyz]/g) || [];
            return consonants.length / (vowels.length || 1);
        };

        // Get word length variance
        const getWordLengthVariance = (str) => {
            const words = str.split(/\s+/);
            if (words.length < 2) return 0;
            
            const lengths = words.map(w => w.length);
            const mean = lengths.reduce((sum, len) => sum + len, 0) / lengths.length;
            
            return lengths.reduce((variance, len) => {
                return variance + Math.pow(len - mean, 2);
            }, 0) / lengths.length;
        };

        const entropy = calculateEntropy(text);
        const ratio = consonantVowelRatio(text);
        const variance = getWordLengthVariance(text);

        // Flags for potential gibberish
        const flags = {
            highEntropy: entropy > 4.2,
            badConsonantRatio: ratio > 3.5 || ratio < 0.3,
            lowVariance: variance < 0.5 && text.length > 20,
            randomCapitalization: (/[A-Z][a-z][A-Z][a-z]/).test(text),
            repeatedPatterns: (/(.{2,})\1{2,}/g).test(text)
        };

        // Count how many flags are triggered
        const flagCount = Object.values(flags).filter(Boolean).length;

        return flagCount >= 2;
    }
};

// Content validation middleware
const validateContent = (req, res, next) => {
    const { title, text } = req.body;
    
    if (title && (contentValidation.containsSpam(title) || contentValidation.isGibberish(title))) {
        return res.status(400).json({ 
            message: 'Title contains inappropriate content or spam patterns' 
        });
    }
    
    if (text && (contentValidation.containsSpam(text) || contentValidation.isGibberish(text))) {
        return res.status(400).json({ 
            message: 'Content contains inappropriate content or spam patterns' 
        });
    }
    
    next();
};

// Rate limiting middleware
const rateLimitMiddleware = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);
        const now = new Date();
        const oneMinute = 60 * 1000;
        
        if (user.lastPostTime && (now - user.lastPostTime) < oneMinute) {
            return res.status(429).json({ 
                message: 'Please wait a minute before posting again' 
            });
        }
        
        if (user.postCount >= 50) { // Daily limit
            const oneDayAgo = new Date(now - 24 * 60 * 60 * 1000);
            if (user.lastPostTime > oneDayAgo) {
                return res.status(429).json({ 
                    message: 'Daily posting limit reached' 
                });
            }
            user.postCount = 0;
        }
        
        next();
    } catch (error) {
        next(error);
    }
};

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

// Generate random nickname
const generateNickname = () => {
    const adjectives = ['Happy', 'Clever', 'Brave', 'Gentle', 'Kind', 'Swift'];
    const nouns = ['Panda', 'Fox', 'Eagle', 'Dolphin', 'Tiger', 'Owl'];
    return `${adjectives[Math.floor(Math.random() * adjectives.length)]}${nouns[Math.floor(Math.random() * nouns.length)]}${Math.floor(Math.random() * 1000)}`;
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, isAdmin } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
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
        
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }
        
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

const paginationMiddleware = (req, res, next) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 9;
    
    req.pagination = {
        skip: (page - 1) * limit,
        limit: limit
    };
    
    next();
};

// Update the GET thoughts route
app.get('/api/thoughts', paginationMiddleware, async (req, res) => {
    try {
        const { skip, limit } = req.pagination;
        const filterType = req.query.filterType || 'all';
        const sortBy = req.query.sortBy || 'newest';
        
        // Build query
        let query = {};
        if (filterType !== 'all') {
            query.type = filterType;
        }
        
        // Build sort options
        let sortOptions = {};
        switch(sortBy) {
            case 'oldest':
                sortOptions = { timestamp: 1 };
                break;
            case 'popular':
                sortOptions = { views: -1 };
                break;
            default: // newest
                sortOptions = { timestamp: -1 };
        }
        
        // Execute query with pagination
        const thoughts = await Thought.find(query)
            .sort(sortOptions)
            .skip(skip)
            .limit(limit);
            
        // Get total count for pagination
        const totalThoughts = await Thought.countDocuments(query);
        
        res.json({
            thoughts,
            totalPages: Math.ceil(totalThoughts / limit),
            currentPage: Math.floor(skip / limit) + 1,
            hasMore: skip + thoughts.length < totalThoughts
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});
// Add this new route to your backend
app.get('/api/thoughts/:id', async (req, res) => {
    try {
        const thought = await Thought.findById(req.params.id);
        if (!thought) {
            return res.status(404).json({ message: 'Thought not found' });
        }
        res.json(thought);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/thoughts', [authMiddleware, rateLimitMiddleware, validateContent], async (req, res) => {
    try {
        const { title, text, type } = req.body;
        
        // Create thought with author
        const thought = new Thought({
            ...req.body,
            author: req.body.author || generateNickname(),
            timestamp: Date.now()
        });
        
        const newThought = await thought.save();
        
        // Update user's post count and time
        const user = await User.findById(req.user.id);
        user.lastPostTime = new Date();
        user.postCount += 1;
        await user.save();
        
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

            // Limit view history to last 100 entries
            if (user.viewHistory.length > 100) {
                user.viewHistory = user.viewHistory.slice(-100);
            }

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
        const userId = req.user.id;
        
        if (!emoji || typeof emoji !== 'string') {
            return res.status(400).json({ message: 'Valid emoji is required' });
        }
        
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
            recentThoughts: await Thought.find().sort({ timestamp: -1 }).limit(10),
            spamStats: {
                lastDayPosts: await Thought.countDocuments({
                    timestamp: { $gte: Date.now() - 24 * 60 * 60 * 1000 }
                }),
                topAuthors: await Thought.aggregate([
                    { $group: { _id: '$author', count: { $sum: 1 } } },
                    { $sort: { count: -1 } },
                    { $limit: 5 }
                ])
            }
        };
        res.json(stats);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});



// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    
    // Specific error handling
    if (err.name === 'ValidationError') {
        return res.status(400).json({ 
            message: 'Validation Error', 
            details: err.errors 
        });
    }
    
    if (err.name === 'MongoError' && err.code === 11000) {
        return res.status(409).json({ 
            message: 'Duplicate key error' 
        });
    }
    
    res.status(500).json({ 
        message: 'Something went wrong!',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ message: 'Route not found' });
});

const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('Connected to MongoDB');
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
            // Start the keep-alive ping
            pingInterval = setInterval(pingServer, PING_INTERVAL);
        });
    })
    .catch((error) => {
        console.error('Could not connect to MongoDB:', error);
    });

// Modified graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    // Clear the ping interval
    if (pingInterval) {
        clearInterval(pingInterval);
    }
    mongoose.connection.close(false, () => {
        console.log('MongoDB connection closed.');
        process.exit(0);
    });
});

module.exports = app;
