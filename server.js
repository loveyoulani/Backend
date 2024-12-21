const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    credentials: true
}));
app.use(express.json());

// MongoDB Schema
const thoughtSchema = new mongoose.Schema({
    title: { type: String, required: true },
    text: { type: String, required: true },
    type: { type: String, required: true },
    date: { type: String, required: true },
    views: { type: Number, default: 0 },
    reactions: { type: Map, of: Number, default: {} },
    timestamp: { type: Number, required: true }
});

const Thought = mongoose.model('Thought', thoughtSchema);

// Root route
app.get('/', (req, res) => {
    res.json({ 
        message: 'Welcome to ThoughtShare API',
        endpoints: {
            getAllThoughts: 'GET /api/thoughts',
            createThought: 'POST /api/thoughts',
            updateViews: 'PATCH /api/thoughts/:id/view',
            addReaction: 'PATCH /api/thoughts/:id/react'
        }
    });
});

// Get all thoughts
app.get('/api/thoughts', async (req, res) => {
    try {
        const thoughts = await Thought.find().sort({ timestamp: -1 });
        res.json(thoughts);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Create new thought
app.post('/api/thoughts', async (req, res) => {
    const thought = new Thought({
        ...req.body,
        timestamp: Date.now()
    });
    try {
        const newThought = await thought.save();
        res.status(201).json(newThought);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Update view count
app.patch('/api/thoughts/:id/view', async (req, res) => {
    try {
        const thought = await Thought.findById(req.params.id);
        if (!thought) {
            return res.status(404).json({ message: 'Thought not found' });
        }
        thought.views = (thought.views || 0) + 1;
        await thought.save();
        res.json(thought);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Add reaction
app.patch('/api/thoughts/:id/react', async (req, res) => {
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
