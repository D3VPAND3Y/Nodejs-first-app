import express from 'express';
import path from 'path';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app = express();

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017', {
    dbName: "backend",
}).then(() => {
    console.log("Connected to MongoDB");
}).catch((err) => {
    console.log("Error connecting to MongoDB");
    console.error(err);
});

// Define user schema
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
});

// Create user model
const User = mongoose.model('User', userSchema);

// Middleware and configurations
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// Middleware to check if user is authenticated
const isAuthenticated = async (req, res, next) => {
    try {
        const token = req.cookies.token;
        if (token) {
            const decoded = jwt.verify(token, 'secret');
            req.user = await User.findById(decoded._id);
            next();
        } else {
            throw new Error('No token found');
        }
    } catch (err) {
        // Redirect to login page if authentication fails
        res.render('login');
    }
};

// Routes

// Home route requires authentication
app.get('/', isAuthenticated, (req, res) => {
    console.log(req.user);
    res.render('logout');
});

// Login route
app.get('/login', (req, res) => {
    res.render('login');
});

// Register route
app.get('/register', (req, res) => {
    res.render('register');
});

// Handle login form submission
app.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.redirect('register');
        }

        const isMatch = await bcrypt.compare(req.body.password, user.password);

        if (!isMatch) {
            return res.render('login', { email: req.body.email, message: "Incorrect password" });
        }

        const token = jwt.sign({ _id: user._id }, 'secret');

        // Set cookie with token for authentication
        res.cookie("token", token, {
            expires: new Date(Date.now() + 900000),
            httpOnly: true,
        });
        res.redirect('/');
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

// Handle registration form submission
app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const userFind = await User.findOne({ email });

        if (userFind) {
            return res.redirect('login');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            name,
            email,
            password: hashedPassword,
        });

        const token = jwt.sign({ _id: user._id }, 'secret');

        // Set cookie with token for authentication
        res.cookie("token", token, {
            expires: new Date(Date.now() + 900000),
            httpOnly: true,
        });
        res.redirect('/');
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
    }
});

// Handle logout
app.post('/logout', (req, res) => {
    // Clear authentication token cookie
    res.clearCookie("token");
    res.redirect('/');
});

// Start server
app.listen(3000, () => {
    console.log('Server started on port 3000');
});
