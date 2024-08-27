const express = require('express');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_secret_key'; // Replace with your secret key

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors());

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

const users = [];

// Helper function to find a user by email
const findUserByEmail = (email) => users.find(user => user.email === email);

// Function to generate a custom token
const generateToken = (email) => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
    const payload = Buffer.from(JSON.stringify({ email, exp: Date.now() + 3600000 })).toString('base64');
    const signature = crypto.createHmac('sha256', SECRET_KEY)
        .update(`${header}.${payload}`)
        .digest('base64');
    return `${header}.${payload}.${signature}`;
};

// Function to verify a custom token
const verifyToken = (token) => {
    const [header, payload, signature] = token.split('.');
    const checkSignature = crypto.createHmac('sha256', SECRET_KEY)
        .update(`${header}.${payload}`)
        .digest('base64');
    if (checkSignature !== signature) return null;

    const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString('utf-8'));
    if (decodedPayload.exp < Date.now()) return null;

    return decodedPayload;
};

// Middleware to authenticate using custom token
const authenticateCustomToken = (req, res, next) => {
    const token = req.cookies.user;

    if (token) {
        const user = verifyToken(token);
        if (user) {
            req.user = user;
            return next();
        } else {
            return res.sendStatus(403);
        }
    } else {
        res.sendStatus(401);
    }
};

// Function to validate email format
const validateEmail = (email) => {
    const emailRegex = /^[a-zA-Z][a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]*@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$/;
    return emailRegex.test(email);
};

// Function to validate password strength
const validatePassword = (password) => {
    const passwordRegex = /^(?=.*[0-9])(?=.*[!@#$%^&*])/;
    return passwordRegex.test(password);
};

// Signup Route
app.post('/signup', async (req, res) => {
    const { name, email, mobile_no, password, confirmPassword } = req.body;

    if (!validateEmail(email)) {
        return res.status(400).json({ message: 'Invalid email format. Email must start with a letter and be in the correct format.' });
    }

    if (!validatePassword(password)) {
        return res.status(400).json({ message: 'Password must contain at least one special character and one numeric digit.' });
    }

    if (password !== confirmPassword) {
        return res.status(400).json({ message: 'Passwords do not match.' });
    }

    if (findUserByEmail(email)) {
        return res.status(400).json({ message: 'User already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { name, email, mobile_no, password: hashedPassword };
    users.push(newUser);

    // Generate a custom token
    const token = generateToken(newUser.email);

    // Set the token in a cookie
    res.cookie('user', token, { httpOnly: true, secure: false, maxAge: 3600000 });
    
    res.status(201).json({ message: 'User created successfully', user: newUser });
});

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = findUserByEmail(email);

    if (!user) {
        return res.status(400).json({ message: 'Email or password is incorrect.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
        return res.status(400).json({ message: 'Email or password is incorrect.' });
    }

    // Generate a custom token
    const token = generateToken(user.email);

    // Set the token in a cookie
    res.cookie('user', token, { httpOnly: true, secure: false, maxAge: 3600000 });
    
    res.json({ message: 'Login successful', token });
});

// Reset Password Route (Requires Authentication)
app.post('/reset-password', authenticateCustomToken, async (req, res) => {
    const { email, newPassword, confirmNewPassword } = req.body;

    if (!validatePassword(newPassword)) {
        return res.status(400).json({ message: 'New password must contain at least one special character and one numeric digit.' });
    }

    if (newPassword !== confirmNewPassword) {
        return res.status(400).json({ message: 'Passwords do not match.' });
    }

    const user = findUserByEmail(email);

    if (!user) {
        return res.status(400).json({ message: 'User not found.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    res.json({ message: 'Password reset successful.' });
});

// Logout Route (Clears token cookie)
app.post('/logout', (req, res) => {
    res.clearCookie('user');
    res.json({ message: 'Logout successful.' });
});
