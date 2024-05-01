const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

// MySQL Connection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'sqluser', 
    password: 'password', 
    database: 'mydb'
});

connection.connect(err => {
    if (err) {
        console.error('Error connecting to MySQL database:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

app.use(express.json());


// User Registration Endpoint
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        const newUser = { username, password_hash: hash };
        connection.query('INSERT INTO Users SET ?', newUser, (err, result) => {
            if (err) {
                console.error('Error registering user:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }

            res.status(201).json({ message: 'User registered successfully' });
        });
    });
});

// User Login Endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    connection.query('SELECT * FROM Users WHERE username = ?', username, (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const user = results[0];

        bcrypt.compare(password, user.password_hash, (err, isValid) => {
            if (err) {
                console.error('Error comparing passwords:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }

            if (!isValid) {
                return res.status(401).json({ message: 'Invalid username or password' });
            }

            const token = jwt.sign({ id: user.id, username: user.username }, 'MY_SECRET_TOKEN', { expiresIn: '1000d'});
            res.status(200).json({ token });
        });
    });
});



function authenticateToken(req, res, next) {
    // Get the JWT token from the Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader.split(' ')[1];
    console.log(token);

    // If token is not provided, return 401 Unauthorized
    if (!token) {
        return res.status(401).json({ message: 'Authentication required' });
    }

    // Verify the JWT token
    jwt.verify(token, 'MY_SECRET_TOKEN', (err, decodedToken) => {
        if (err) {
            console.error('Error verifying token:', err);
            return res.status(403).json({ message: 'Invalid token' });
        }
        // If token is valid, set the user object in the request
        req.user = decodedToken;
        next(); // Call the next middleware
    });
}




// CRUD Endpoints for Tasks

// Retrieve all tasks
app.get('/tasks',authenticateToken,(req, res) => {
    connection.query('SELECT * FROM Tasks WHERE assignee_id = ?', req.user.id, (err, results) => {
        if (err) {
            console.error('Error retrieving tasks:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }
        res.status(200).json(results);
    });
});

// Create a new task
app.post('/tasks', authenticateToken, (req, res) => {
    const { title, description, status } = req.body;
    const assignee_id = req.user.id;

    const newTask = { title, description, status, assignee_id };
    connection.query('INSERT INTO Tasks SET ?', newTask, (err, result) => {
        if (err) {
            console.error('Error creating task:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }
        res.status(201).json({ id: result.insertId, ...newTask });
    });
});

// Update a task by ID
app.put('/tasks/:id', authenticateToken, (req, res) => {
    const taskId = req.params.id;
    const { title, description, status } = req.body;

    connection.query('UPDATE Tasks SET title = ?, description = ?, status = ? WHERE id = ? AND assignee_id = ?', [title, description, status, taskId, req.user.id], (err, result) => {
        if (err) {
            console.error('Error updating task:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Task not found or unauthorized' });
        }

        res.status(200).json({ id: taskId, title, description, status });
    });
});

// Delete a task by ID
app.delete('/tasks/:id', authenticateToken, (req, res) => {
    const taskId = req.params.id;

    connection.query('DELETE FROM Tasks WHERE id = ? AND assignee_id = ?', [taskId, req.user.id], (err, result) => {
        if (err) {
            console.error('Error deleting task:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Task not found or unauthorized' });
        }

        res.status(204).send();
    });
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
