const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

const ALLOWED_USERS_FILE = 'D:/Squid/etc/squid/allowed_users.txt';
const BLOCKED_FILE = 'D:/Squid/etc/squid/blocked_domains.txt';

// Middleware for parsing form data and managing sessions
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(
    session({
        secret: 'captive-portal-secret',
        resave: false,
        saveUninitialized: true,
    })
);

// SQLite setup
const DB_FILE = './users.db';
const db = new sqlite3.Database(DB_FILE, (err) => {
    if (err) console.error('Error opening database:', err.message);
    else {
        console.log('Connected to SQLite database.');
        db.serialize(() => {
            db.run(`
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT
                )
            `);
            db.run(`
                CREATE TABLE IF NOT EXISTS admins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT
                )
            `);

            db.get('SELECT COUNT(*) AS count FROM admins', (err, row) => {
                if (err) console.error('Error querying admins:', err.message);
                if (row.count === 0) {
                    const sampleAdmins = [{ username: 'admin', password: 'adminpass' }];
                    sampleAdmins.forEach(({ username, password }) => {
                        bcrypt.hash(password, 10, (err, hash) => {
                            if (!err) {
                                db.run(
                                    `INSERT INTO admins (username, password) VALUES (?, ?)`,
                                    [username, hash]
                                );
                            }
                        });
                    });
                }
            });
        });
    }
});

// Restart Squid Proxy
const restartSquid = () => {
    const exec = require('child_process').exec;
    const SQUID_EXECUTABLE = 'D:\\Squid\\bin\\squid.exe';
    exec(`${SQUID_EXECUTABLE} -k reconfigure`, (error, stdout, stderr) => {
        if (error) console.error(`Error restarting Squid: ${error.message}`);
        if (stderr) console.error(`Squid stderr: ${stderr}`);
        console.log(`Squid restarted: ${stdout}`);
    });
};

// Add IP to allowed_users.txt
const logIpAndRestartSquid = (ip) => {
    const allowedUsers = fs.existsSync(ALLOWED_USERS_FILE)
        ? fs.readFileSync(ALLOWED_USERS_FILE, 'utf-8').split('\n')
        : [];
    if (!allowedUsers.includes(ip)) {
        fs.appendFileSync(ALLOWED_USERS_FILE, `${ip}\n`);
        console.log(`IP ${ip} added to allowed_users.txt`);
        restartSquid();
    }
};

// Routes
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/home.html');
});

app.post('/login', (req, res) => {
    const { username, password, role } = req.body;

    const table = role === 'admin' ? 'admins' : 'users';
    db.get(`SELECT password FROM ${table} WHERE username = ?`, [username], (err, row) => {
        if (err) res.status(500).send('<h1>Internal Server Error</h1>');
        else if (row) {
            bcrypt.compare(password, row.password, (err, result) => {
                if (result) {
                    req.session.user = { username, role };
                    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
                    logIpAndRestartSquid(ip.split(',')[0].trim().split(':')[0]);
                    if (role === 'admin') res.redirect('/admin/dashboard');
                    else res.send('<h1>User Access Granted</h1>');
                } else res.send('<h1>Invalid Credentials</h1>');
            });
        } else res.send('<h1>Invalid Credentials</h1>');
    });
});

// Admin Dashboard
app.get('/admin/dashboard', (req, res) => {
    if (req.session.user && req.session.user.role === 'admin') {
        res.sendFile(__dirname + '/public/admin/admin_dashboard.html');
    } else {
        res.status(403).send('<h1>Forbidden</h1>');
    }
});

app.post('/admin/block-site', (req, res) => {
    if (req.session.user && req.session.user.role === 'admin') {
        const { block_url } = req.body;
        const domain = block_url.match(/:\/\/(www\.)?([a-zA-Z0-9.-]+)/)?.[2];
        if (domain) {
            const blockedSites = fs.existsSync(BLOCKED_FILE)
                ? fs.readFileSync(BLOCKED_FILE, 'utf-8').split('\n')
                : [];
            if (!blockedSites.includes(domain)) {
                fs.appendFileSync(BLOCKED_FILE, `${domain}\n`);
                console.log(`Domain ${domain} added to blocked_domains.txt`);
                restartSquid();
                res.send('<h1>Site Blocked</h1>');
            } else res.send('<h1>Site Already Blocked</h1>');
        } else res.send('<h1>Invalid URL</h1>');
    } else {
        res.status(403).send('<h1>Forbidden</h1>');
    }
});

app.listen(PORT, () => {
    console.log(`Captive Portal running on port ${PORT}`);
});
