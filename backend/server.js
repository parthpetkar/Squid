const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Path to allowed users file
const ALLOWED_USERS_FILE = 'D:/Squid/etc/squid/allowed_users.txt';

// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files for the login page
app.use(express.static('public'));

// Display the login page
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// Function to restart Squid proxy
const restartSquid = () => {
    const exec = require('child_process').exec;
    const SQUID_EXECUTABLE = 'D:\\Squid\\bin\\squid.exe';
    exec(`${SQUID_EXECUTABLE} -k reconfigure`, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error restarting Squid: ${error.message}`);
            return;
        }
        if (stderr) {
            console.error(`Squid stderr: ${stderr}`);
        }
        console.log(`Squid restarted: ${stdout}`);
    });
};

// Handle login form submission
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Mock authentication (replace with real authentication logic)
    if (username === 'user' && password === 'pass') {
        const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

        // Extract only the IP address from the forwarded-for header or connection remote address
        const ip = clientIp.split(',')[0].trim();

        // Check if the IP already exists in the allowed_users.txt file
        const allowedUsers = fs.existsSync(ALLOWED_USERS_FILE) ? fs.readFileSync(ALLOWED_USERS_FILE, 'utf-8').split('\n') : [];
        if (!allowedUsers.includes(ip)) {
            // Append the IP to a new line in the allowed_users.txt file
            fs.appendFileSync(ALLOWED_USERS_FILE, `${ip}\n`);
            console.log(`IP ${ip} added to allowed_users.txt`);
        }

        // Restart Squid to apply changes
        restartSquid();

        res.send('<h1>Access Granted</h1>');
    } else {
        res.send('<h1>Invalid Credentials</h1>');
    }
});

// Watch the allowed_users.txt file for changes and restart Squid
fs.watch(ALLOWED_USERS_FILE, (eventType, filename) => {
    if (eventType === 'change') {
        console.log(`${filename} changed. Restarting Squid Proxy...`);
        restartSquid();
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Captive Portal running on port ${PORT}`);
});
