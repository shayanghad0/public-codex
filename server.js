const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcrypt');
const session = require('express-session');
const archiver = require('archiver');

const app = express();
const PORT = 5000;

// Middleware
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'file-sharing-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


// Database functions
const loadDB = () => {
  try {
    return JSON.parse(fs.readFileSync('database.json', 'utf8'));
  } catch {
    return { users: [], repositories: [] };
  }
};

const saveDB = (data) => {
  fs.writeFileSync('database.json', JSON.stringify(data, null, 2));
};

// Hash password function
const hashPassword = async (password) => {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
};

// Verify password function
const verifyPassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

// Initialize database with hashed passwords
const initializeDB = async () => {
  if (!fs.existsSync('database.json')) {
    const initialData = {
      users: [
        {
          id: 1,
          username: 'shayanghad0',
          password: await hashPassword('123'),
          role: 'admin',
          createdAt: new Date().toISOString()
        }
      ],
      repositories: []
    };
    saveDB(initialData);
  } else {
    // Check if passwords are already hashed, if not, hash them
    const db = loadDB();
    let needsUpdate = false;
    
    for (let user of db.users) {
      // Check if password is already hashed (bcrypt hashes start with $2b$)
      if (!user.password.startsWith('$2b$')) {
        user.password = await hashPassword(user.password);
        needsUpdate = true;
      }
    }
    
    if (needsUpdate) {
      saveDB(db);
    }
  }
};
