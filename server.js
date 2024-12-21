// backend/server.js
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
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

// Routes
app.get('/api/thoughts', async (req, res) => {
    try {
        const thoughts = await Thought.find().sort({ timestamp: -1 });
        res.json(thoughts);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

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

app.patch('/api/thoughts/:id/view', async (req, res) => {
    try {
        const thought = await Thought.findById(req.params.id);
        thought.views = (thought.views || 0) + 1;
        await thought.save();
        res.json(thought);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

app.patch('/api/thoughts/:id/react', async (req, res) => {
    try {
        const thought = await Thought.findById(req.params.id);
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

const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    })
    .catch((error) => {
        console.error('Could not connect to MongoDB:', error);
    });
