const express = require('express');
const router = express.Router();
const userModel = require('../models/user.model');
const { body, validationResult } = require('express-validator');

router.get('/register', (req, res) => {
    res.render('register', {
        message: null,
        errors: [],
        success: req.query.success === 'true'
    });
});

router.post(
    '/register',
    body('email').trim().isEmail(),
    body('password').trim().isLength({ min: 5 }),
    body('username').trim().isLength({ min: 3 }),
    async (req, res) => {
        const errors = validationResult(req);

        console.log('Validation errors:', errors);
        if (!errors.isEmpty()) {
            return res.status(400).render('register', {
                errors: errors.array(),
                message: 'Invalid data',
                success: false
            });
        }

        try {
            const { email, username, password } = req.body;
            console.log('Trying to create user with:', { email, username, password });

            const newUser = await userModel.create({
                email,
                username,
                password
            });

            console.log('User created successfully:', newUser);
            res.redirect('/user/register?success=true');
        } catch (error) {
            console.error('Database error:', error);
            if (error.code === 11000) {
                return res.status(400).render('register', {
                    message: 'Username or email already exists',
                    errors: [],
                    success: false
                });
            }
            res.status(500).render('register', {
                message: 'Database error',
                errors: [],
                success: false,
                error: error.message
            });
        }
    }
);

module.exports = router;