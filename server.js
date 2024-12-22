const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

// Schema Definitions
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    viewHistory: [{
        thoughtId: { type: mongoose.Schema.Types.ObjectId, ref: 'Thought' },
        timestamp: { type: Date, default: Date.now }
    }],
    tagPreferences: {
        type: Map,
        of: Number,
        default: new Map()
    }
}, { timestamps: true });

const thoughtSchema = new mongoose.Schema({
    title: { type: String, required: true },
    text: { type: String, required: true },
    author: { type: String, required: true },
    type: { type: String, required: true },
    tags: [String],
    views: { type: Number, default: 0 },
    reactions: {
        type: Map,
        of: Number,
        default: new Map()
    },
    timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Thought = mongoose.model('Thought', thoughtSchema);

// Middleware definitions
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'Authentication required' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

const adminMiddleware = (req, res, next) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

const app = express();

// Security middleware
app.use(helmet());
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
}));

app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    credentials: true
}));

app.use(express.json({ limit: '10kb' })); // Limit payload size

// Enhanced spam detection system
const spamDetection = {
    repetitivePattern: /(.)\1{4,}/,
    excessiveCaps: /[A-Z]{5,}/,
    spamPhrases: [
        'buy now', 'click here', 'free offer', 'limited time',
        'make money', 'winner', 'discount', 'subscribe',
        'order now', 'act now', 'call now', 'apply now',
        'prescription', 'medication', 'casino', 'loan',
        'investment', 'bitcoin', 'crypto', 'lottery',
        'warranty', 'free money', 'work from home'
    ],
    urlPattern: /(https?:\/\/[^\s]+)/g,
    emailPattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    phonePattern: /(\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}/g,

    getCharacterRatios(text) {
        const total = text.length;
        if (total === 0) return { caps: 0, special: 0 };
        
        const caps = (text.match(/[A-Z]/g) || []).length / total;
        const special = (text.match(/[^a-zA-Z0-9\s]/g) || []).length / total;
        
        return { caps, special };
    },

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

    containsSpam(text, isComment = false) {
        if (!text || text.trim().length === 0) return false;
        
        const allowedPatterns = [
            /x+d+/i,
            /l+o+l+/i,
            /h+a+h+a+/i,
            /:\)|:\(|:D|:P|XD|<3/
        ];
        
        let sanitizedText = text;
        allowedPatterns.forEach(pattern => {
            sanitizedText = sanitizedText.replace(pattern, '');
        });
        
        const ratios = this.getCharacterRatios(sanitizedText);
        const entropy = this.calculateEntropy(sanitizedText);
        
        return (
            this.repetitivePattern.test(sanitizedText) ||
            ratios.caps > 0.5 ||
            ratios.special > 0.3 ||
            entropy < 2.0 ||
            this.spamPhrases.some(phrase => 
                sanitizedText.toLowerCase().includes(phrase.toLowerCase())
            ) ||
            (!isComment && (
                this.urlPattern.test(sanitizedText) ||
                this.emailPattern.test(sanitizedText) ||
                this.phonePattern.test(sanitizedText)
            ))
        );
    }
};

// Password validation
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

// Utility function for generating nicknames
const generateNickname = () => {
    const adjectives = ['Happy', 'Lucky', 'Sunny', 'Clever', 'Bright', 'Swift'];
    const nouns = ['Fox', 'Bear', 'Eagle', 'Wolf', 'Lion', 'Tiger'];
    const randomNum = Math.floor(Math.random() * 1000);
    
    return `${adjectives[Math.floor(Math.random() * adjectives.length)]}${
        nouns[Math.floor(Math.random() * nouns.length)]}${randomNum}`;
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, isAdmin } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }
        
        if (!validatePassword(password)) {
            return res.status(400).json({
                message: 'Password must be at least 8 characters and contain uppercase, lowercase, number, and special character'
            });
        }
        
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const user = new User({
            username,
            password: hashedPassword,
            isAdmin: isAdmin && process.env.ADMIN_SECRET === req.body.adminSecret
        });
        
        await user.save();
        
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
        
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }
        
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { id: user._id, username: user.username, isAdmin: user.isAdmin },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRATION || '24h' }
        );
        
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Thought Routes
app.get('/api/thoughts', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        
        const thoughts = await Thought.find()
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(limit);
            
        const total = await Thought.countDocuments();
        
        res.json({
            thoughts,
            currentPage: page,
            totalPages: Math.ceil(total / limit),
            totalThoughts: total
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/thoughts', authMiddleware, async (req, res) => {
    try {
        const { title, text, type, tags = [] } = req.body;
        
        if (!title || !text || !type) {
            return res.status(400).json({ message: 'Title, text, and type are required' });
        }
        
        if (spamDetection.containsSpam(title) || spamDetection.containsSpam(text)) {
            return res.status(400).json({ message: 'Content contains spam or inappropriate content' });
        }
        
        const thought = new Thought({
            title,
            text,
            type,
            tags,
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

        const user = await User.findById(req.user.id);
        if (user) {
            // Limit view history to last 100 entries
            user.viewHistory = [
                ...user.viewHistory.slice(-99),
                {
                    thoughtId: thought._id,
                    timestamp: new Date()
                }
            ];

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
        const { emoji } = req.body;
        
        if (!emoji) {
            return res.status(400).json({ message: 'Emoji is required' });
        }
        
        const thought = await Thought.findById(req.params.id);
        if (!thought) {
            return res.status(404).json({ message: 'Thought not found' });
        }
        
        thought.reactions.set(emoji, (thought.reactions.get(emoji) || 0) + 1);
        await thought.save();
        res.json(thought);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

app.get('/api/thoughts/recommended', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const thoughts = await Thought.find()
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(limit);
        
        const scoredThoughts = thoughts.map(thought => ({
            thought,
            score: thought.tags.reduce((score, tag) => 
                score + (user.tagPreferences.get(tag) || 0), 0)
        }));

        const recommended = scoredThoughts
            .sort((a, b) => b.score - a.score)
            .map(item => item.thought);

        res.json(recommended);
    } catch (error) {
        res.status(500).json({ message: error.message });
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
        const [totalThoughts, totalUsers, recentThoughts, userStats] = await Promise.all([
            Thought.countDocuments(),
            User.countDocuments(),
            Thought.find()
                .sort({ timestamp: -1 })
                .limit(10)
                .select('title author views timestamp'),
            User.aggregate([
                {
                    $group: {
                        _id: null,
                        averageViews: { $avg: { $size: "$viewHistory" } },
                        totalActiveUsers: {
                            $sum: {
                                $cond: [
                                    { $gt: [{ $size: "$viewHistory" }, 0] },
                                    1,
                                    0
                                ]
                            }
                        }
                    }
                }
            ])
        ]);

        const stats = {
            totalThoughts,
            totalUsers,
            recentThoughts,
            userStats: userStats[0] || { averageViews: 0, totalActiveUsers: 0 },
            timestamp: new Date()
        };

        res.json(stats);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ 
        message: process.env.NODE_ENV === 'development' 
            ? err.message 
            : 'Something went wrong!' 
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ message: 'Route not found' });
});

// Graceful shutdown function
const gracefulShutdown = async () => {
    console.log('Received shutdown signal. Starting graceful shutdown...');
    
    try {
        // Close MongoDB connection
        await mongoose.connection.close(false);
        console.log('MongoDB connection closed.');
        
        // Allow ongoing requests to complete (wait for 10 seconds max)
        const shutdownDelay = 10000;
        console.log(`Waiting ${shutdownDelay}ms for ongoing requests to complete...`);
        setTimeout(() => {
            console.log('Shutting down application...');
            process.exit(0);
        }, shutdownDelay);
    } catch (error) {
        console.error('Error during shutdown:', error);
        process.exit(1);
    }
};

// Server startup
const startServer = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log('Connected to MongoDB');

        const PORT = process.env.PORT || 3000;
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
};

// Shutdown handlers
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Start the server
startServer();

module.exports = app;
