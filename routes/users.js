const User = require('../models/user');

var express = require('express');
const {compare, genSalt, hash} = require("bcrypt");
const {sign} = require("jsonwebtoken");
var router = express.Router();

router.get('/', async (req, res) => {
    try {
        const users = await User.findAll();
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get user by id
router.get('/:id', async (req, res) => {
    try {
        const user = await User.findByPk(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create a new user
router.post('/', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if a user with the same username or email already exists
        const existingUser = await User.findOne( { where: { email } });

        // If a user with the same username or email exists, return an error response
        if (existingUser) {
            return res.status(400).json({ message: 'Username or email already exists.' });
        }
        const user = await User.create(req.body);
        res.status(201).json(user);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Update a user by id
router.put('/:id', async (req, res) => {
    try {
        const user = await User.findByPk(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // If a password is being updated, hash it
        if (req.body.password) {
            const salt = await genSalt();
            req.body.password = await hash(req.body.password, salt);
        }

        await user.update(req.body);
        res.status(200).json(user);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Delete a user by id
router.delete('/:id', async (req, res) => {
    try {
        const user = await User.findByPk(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        await user.destroy();
        res.status(200).json({ message: 'User deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


router.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        const existingUser = await User.findOne({ where: { email } });

        // If a user with the same username or email exists, return an error response
        if (existingUser) {
            return res.status(400).json({ message: 'Username or email already exists.' });
        }
        const user = await User.create(req.body);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ where: { username } });

        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        console.log(user.password, password, await compare(password, user.password));
        const validPassword = await compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const token = sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, {
            expiresIn: '1h'
        });

        res.status(200).json({ token });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});


module.exports = router;
