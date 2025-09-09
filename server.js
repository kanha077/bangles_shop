// --- Import Required Packages ---
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const os = require('os');

// --- Basic Setup ---
const app = express();
const PORT = 3000;
let db;

// --- Nodemailer Configuration ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'yashvijay814@gmail.com',
        pass: 'dlei duao advq gioi'
    }
});

// --- Express Middleware ---
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));


// --- Main Server and Database Logic ---
(async () => {
    db = await open({
        filename: 'database.sqlite',
        driver: sqlite3.Database
    });

    // Create Tables with corrected syntax
    await db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, is_verified INTEGER DEFAULT 0, verification_token TEXT, is_admin INTEGER DEFAULT 0)`);
    await db.exec(`CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL, message TEXT NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    await db.exec(`CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, products TEXT NOT NULL, total_price REAL NOT NULL, customer_name TEXT NOT NULL, mobile_number TEXT NOT NULL, whatsapp_number TEXT, shipping_address TEXT NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))`);
    await db.exec(`CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, price REAL NOT NULL, description TEXT, image_urls TEXT NOT NULL, category TEXT NOT NULL)`);

    // Create default admin user
    const userCount = await db.get("SELECT COUNT(*) as count FROM users WHERE username = 'owner'");
    if (userCount.count === 0) {
        const password_hash = await bcrypt.hash('secretpassword', 10);
        await db.run("INSERT INTO users (username, email, password_hash, is_verified, is_admin) VALUES ('owner', 'owner@email.com', ?, 1, 1)", [password_hash]);
        console.log('Default admin user created.');
    }

    console.log('Database connected and all tables are ready.');

    // --- All App Routes ---
    
    app.post('/submit-contact', async (req, res) => {
        const { name, email, message } = req.body;
        try {
            await db.run('INSERT INTO messages (name, email, message) VALUES (?, ?, ?)', [name, email, message]);
            res.status(200).json({ message: 'Message saved successfully!' });
        } catch (error) { res.status(500).json({ message: 'Server error while saving message.' }); }
    });

    app.post('/signup', async (req, res) => {
        const { username, password, email } = req.body;
        try {
            const password_hash = await bcrypt.hash(password, 10);
            const verification_token = crypto.randomBytes(32).toString('hex');
            await db.run('INSERT INTO users (username, email, password_hash, verification_token, is_admin) VALUES (?, ?, ?, ?, 0)', [username, email, password_hash, verification_token]);
            const verificationLink = `http://localhost:${PORT}/verify-email?token=${verification_token}`;
            await transporter.sendMail({
                from: `"Meera Bangles" <${transporter.options.auth.user}>`,
                to: email, subject: 'Please Verify Your Email Address',
                html: `<p>Please click the link to verify your email:</p><a href="${verificationLink}">Verify My Email</a>`
            });
            res.status(201).json({ message: 'Account created! Please check your email.' });
        } catch (error) {
            if (error.code === 'SQLITE_CONSTRAINT') return res.status(409).json({ message: 'Username or email already exists.' });
            console.error('Signup Error:', error);
            res.status(500).json({ message: 'Server error.' });
        }
    });

    app.get('/verify-email', async (req, res) => {
        const { token } = req.query;
        const user = await db.get('SELECT * FROM users WHERE verification_token = ?', [token]);
        if (!user) return res.status(400).send('<h1>Invalid link.</h1>');
        await db.run('UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?', [user.id]);
        res.send('<h1>Email Verified!</h1><p>You can now <a href="/login.html">log in</a>.</p>');
    });

    app.post('/login', async (req, res) => {
        const { username, password } = req.body;
        try {
            const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
            if (!user) return res.status(401).json({ message: 'Invalid credentials.' });
            if (user.is_verified === 0 && user.is_admin === 0) return res.status(403).json({ message: 'Please verify your email.' });
            const passwordMatches = await bcrypt.compare(password, user.password_hash);
            if (passwordMatches) {
                res.status(200).json({ message: 'Login successful!', isAdmin: user.is_admin === 1, userId: user.id });
            } else {
                res.status(401).json({ message: 'Invalid credentials.' });
            }
        } catch (error) {
            console.error("Login Error:", error);
            res.status(500).json({ message: "Server error during login." });
        }
    });
    
    app.post('/api/orders', async (req, res) => {
        const { userId, cartItems, totalPrice, fullName, mobileNumber, whatsappNumber, address } = req.body;
        if (!userId || !cartItems || !totalPrice || !fullName || !mobileNumber || !address) {
            return res.status(400).json({ message: 'Missing required order details.' });
        }
        try {
            await db.run('INSERT INTO orders (user_id, products, total_price, customer_name, mobile_number, whatsapp_number, shipping_address) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [userId, JSON.stringify(cartItems), totalPrice, fullName, mobileNumber, whatsappNumber, address]);
            res.status(201).json({ message: 'Order placed successfully!' });
        } catch (error) {
            console.error('Error placing order:', error);
            res.status(500).json({ message: 'Failed to place order.' });
        }
    });
    
    app.get('/api/products', async (req, res) => {
        const { category } = req.query;
        let query = 'SELECT * FROM products';
        const params = [];
        if (category && category !== 'All') {
            query += ' WHERE category = ?';
            params.push(category);
        }
        query += ' ORDER BY id DESC';
        try {
            const products = await db.all(query, params);
            products.forEach(p => { if (p.image_urls) p.image_urls = JSON.parse(p.image_urls); });
            res.json(products);
        } catch (error) { res.status(500).json({ message: 'Failed to fetch products.' }); }
    });

    app.get('/api/products/:id', async (req, res) => {
        try {
            const product = await db.get('SELECT * FROM products WHERE id = ?', [req.params.id]);
            if (product) {
                if (product.image_urls) product.image_urls = JSON.parse(product.image_urls);
                res.json(product);
            } else { res.status(404).json({ message: 'Product not found.' }); }
        } catch (error) { res.status(500).json({ message: 'Failed to fetch product.' }); }
    });

    app.post('/api/products', async (req, res) => {
        const { name, price, description, imageUrls, category } = req.body;
        if (!name || !price || !imageUrls || !category) {
            return res.status(400).json({ message: 'All fields are required.' });
        }
        try {
            await db.run(
                'INSERT INTO products (name, price, description, image_urls, category) VALUES (?, ?, ?, ?, ?)',
                [name, parseFloat(price), description, JSON.stringify(imageUrls), category]
            );
            res.status(201).json({ message: 'Product added successfully!' });
        } catch (error) { res.status(500).json({ message: 'Failed to add product.' }); }
    });
    
    // Admin API Routes
    app.get('/api/users', async (req, res) => {
        const users = await db.all('SELECT id, username, email FROM users WHERE is_admin = 0');
        res.json(users);
    });
    app.delete('/api/users/:id', async (req, res) => {
        const userId = req.params.id;
        try {
            await db.run('DELETE FROM orders WHERE user_id = ?', [userId]);
            const result = await db.run('DELETE FROM users WHERE id = ? AND is_admin = 0', [userId]);
            if (result.changes > 0) res.json({ message: `User #${userId} deleted.` });
            else res.status(404).json({ message: 'User not found.' });
        } catch (error) { res.status(500).json({ message: 'Failed to delete user.' }); }
    });
    app.get('/api/orders', async (req, res) => {
        const orders = await db.all(`SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.timestamp DESC`);
        res.json(orders);
    });
    app.get('/api/messages', async (req, res) => {
        const messages = await db.all('SELECT * FROM messages ORDER BY timestamp DESC');
        res.json(messages);
    });
    app.delete('/api/messages/:id', async (req, res) => {
        const messageId = req.params.id;
        const result = await db.run('DELETE FROM messages WHERE id = ?', [messageId]);
        if (result.changes > 0) res.json({ message: `Message #${messageId} deleted.` });
        else res.status(404).json({ message: 'Message not found.' });
    });

    // --- Start the Server ---
    app.listen(PORT, '0.0.0.0', () => {
        const networkInterfaces = os.networkInterfaces();
        let ip = 'localhost';
        for (const name of Object.keys(networkInterfaces)) {
            for (const net of networkInterfaces[name]) {
                if (net.family === 'IPv4' && !net.internal) { ip = net.address; }
            }
        }
        console.log(`✅ Server is running!`);
        console.log(`   - Local:   http://192.168.29.183:${PORT}`);
        console.log(`   - Network: http://${ip}:${PORT}`);
    });
})();