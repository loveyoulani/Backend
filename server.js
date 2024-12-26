const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const https = require('https');
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
    // Remove 'https://' from the URL as it's handled by the options
    const hostname = (process.env.APP_URL || 'backend-7sk4.onrender.com').replace(/^https?:\/\//, '');
    
    const options = {
        hostname: hostname,
        path: '/api/ping',
        method: 'GET',
        port: 443,
        headers: {
            'User-Agent': 'render-ping/1.0',
        }
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
    // Comprehensive spam detection
    containsSpam: (text) => {
        if (!text) return false;
        
        const lowerText = text.toLowerCase();

        // Common spam phrase combinations
        const spamPhrases = [
            // Marketing/Sales Spam
            ['buy', 'discount', 'offer', 'sale', 'deal', 'limited', 'exclusive', 'shop', 'price'],
            ['free', 'gift', 'bonus', 'prize', 'winner', 'won', 'reward', 'claim'],
            ['guarantee', 'guaranteed', 'promise', 'lifetime', 'satisfaction'],
            ['urgent', 'act now', 'don\'t wait', 'hurry', 'expires', 'deadline'],
            
            // Financial Spam
            ['money', 'cash', 'dollars', 'profit', 'income', 'earn', 'wealthy', 'rich'],
            ['investment', 'invest', 'stocks', 'crypto', 'bitcoin', 'trading', 'forex'],
            ['loan', 'credit', 'debt', 'mortgage', 'refinance', 'insurance'],
            ['roi', 'return on investment', 'passive income', 'revenue'],
            
            // Employment Spam
            ['work from home', 'remote work', 'be your own boss', 'quit your job'],
            ['make money online', 'online business', 'side hustle', 'part-time'],
            ['opportunity', 'opportunities', 'position', 'hiring', 'recruitment'],
            
            // Health/Medicine Spam
            ['weight loss', 'diet', 'fat', 'slim', 'physicians', 'doctors'],
            ['pills', 'medication', 'medicine', 'prescription', 'pharmacy'],
            ['cure', 'treatment', 'remedy', 'solution', 'breakthrough'],
            
            // Adult Content Spam
            ['adult', 'dating', 'singles', 'match', 'meet', 'hookup'],
            ['hot', 'sexy', 'seductive', 'intimate', 'passionate'],
            
            // Gambling Spam
            ['casino', 'poker', 'gambling', 'bet', 'lottery', 'jackpot'],
            ['slots', 'roulette', 'blackjack', 'bingo', 'wagering'],
            
            // Tech Scam Spam
            ['tech support', 'customer service', 'helpdesk', 'support team'],
            ['account', 'login', 'password', 'security', 'verify', 'verification'],
            ['subscription', 'subscribe', 'unsubscribe', 'notification'],
            
            // Miscellaneous Spam
            ['congratulations', 'selected', 'chosen', 'special', 'vip'],
            ['miracle', 'amazing', 'incredible', 'unbelievable', 'stunning'],
            ['secret', 'hidden', 'private', 'confidential', 'exclusive'],
            ['risk-free', 'no risk', 'foolproof', 'proven', 'tested']
        ];

        // URL and contact patterns
        const suspiciousPatterns = {
            urls: /(?:https?:\/\/[^\s]*\.(?:xyz|tk|pw|cc|fun|link|click|buzz|gb|gq|ml|ga|cf|ws|top|monster|science|party|kim|men|loan|work|racing|date|win|bid|stream|download|xin|vip|name|site|online|icu|cyou|hair|cam|mom|review|group|live|world|today))/gi,
            emails: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
            phones: /(?:[\+\(]?[1-9][0-9 .\-\(\)]{8,}[0-9])/g,
            crypto: /(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})/g
        };

        // Check for suspicious patterns
        for (const [key, pattern] of Object.entries(suspiciousPatterns)) {
            if (pattern.test(text)) return true;
        }

        // Check for spam phrase combinations
        let spamScore = 0;
        const words = lowerText.split(/\s+/);
        
        for (const phraseGroup of spamPhrases) {
            let groupMatches = 0;
            for (const phrase of phraseGroup) {
                if (lowerText.includes(phrase)) {
                    groupMatches++;
                }
            }
            // If multiple matches from the same group, increase spam score
            if (groupMatches >= 2) {
                spamScore += groupMatches;
            }
        }

        // Additional spam indicators
        const indicators = {
            excessiveCaps: (text.match(/[A-Z]/g) || []).length / text.length > 0.5,
            repeatedChars: /(.)\1{7,}/g.test(text),
            excessivePunctuation: /[!?.,]{4,}/g.test(text),
            suspiciousFormatting: /[*_~]{3,}/g.test(text),
            numbersAndSymbols: (text.match(/[\d$€£¥%@#*]+/g) || []).length / words.length > 0.3
        };

        // Check message structure
        const structureChecks = {
            shortWithUrl: words.length < 5 && suspiciousPatterns.urls.test(text),
            repeatedWords: words.some((word, i) => word.length > 3 && word === words[i - 1]),
            allCapsWords: words.filter(word => word.length > 3 && word === word.toUpperCase()).length > words.length * 0.3
        };

        // Calculate final spam likelihood
        let spamLikelihood = spamScore;
        spamLikelihood += Object.values(indicators).filter(Boolean).length * 2;
        spamLikelihood += Object.values(structureChecks).filter(Boolean).length * 2;

        // Return true if spam likelihood is too high
        return spamLikelihood >= 4;
    },

    // Rate limiting check
    isRapidPosting: (lastPostTime) => {
        if (!lastPostTime) return false;
        const timeSinceLastPost = Date.now() - new Date(lastPostTime).getTime();
        return timeSinceLastPost < 10000; // 10 seconds between posts
    }
};

// Content validation middleware
const validateContent = (req, res, next) => {
    const { title, text } = req.body;
    
    if (title && contentValidation.containsSpam(title)) {
        return res.status(400).json({ 
            message: 'Detected spam patterns in title' 
        });
    }
    
    if (text && contentValidation.containsSpam(text)) {
        return res.status(400).json({ 
            message: 'Detected spam patterns in content' 
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

// Modified graceful shutdown with proper async handling
process.on('SIGTERM', async () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    // Clear the ping interval
    if (pingInterval) {
        clearInterval(pingInterval);
    }
    try {
        // Close mongoose connection properly
        await mongoose.connection.close();
        console.log('MongoDB connection closed.');
        process.exit(0);
    } catch (err) {
        console.error('Error during shutdown:', err);
        process.exit(1);
    }
});

module.exports = app;
