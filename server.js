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


// Authentication middleware
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send('Access denied');
  }
  next();
};

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const repoId = req.params.id;
    const uploadPath = path.join(__dirname, 'uploads', repoId);
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});

const upload = multer({ storage });

// Routes
app.get('/', (req, res) => {
  if (req.session.user) {
    if (req.session.user.role === 'admin') {
      return res.redirect('/admin/dashboard');
    } else {
      return res.redirect('/dev/dashboard');
    }
  }
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password, rememberMe } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.username === username);
  
  if (user && await verifyPassword(password, user.password)) {
    req.session.user = user;
    
    // Extend session duration if Remember Me is checked
    if (rememberMe) {
      req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
    } else {
      req.session.cookie.maxAge = 24 * 60 * 60 * 1000; // 1 day
    }
    
    if (user.role === 'admin') {
      res.redirect('/admin/dashboard');
    } else {
      res.redirect('/dev/dashboard');
    }
  } else {
    res.render('login', { error: 'Invalid credentials' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});


// Admin routes
app.get('/admin/dashboard', requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  res.render('admin/dashboard', { 
    user: req.session.user, 
    users: db.users,
    repositories: db.repositories 
  });
});

app.get('/admin/user', requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  res.render('admin/users', { 
    user: req.session.user, 
    users: db.users.filter(u => u.role === 'developer') 
  });
});

app.get('/admin/user/manage/:id', requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  const userId = parseInt(req.params.id);
  const targetUser = db.users.find(u => u.id === userId);
  
  if (!targetUser) {
    return res.status(404).send('User not found');
  }
  
  res.render('admin/manage-user', { 
    user: req.session.user, 
    targetUser 
  });
});

app.post('/admin/user/create', requireAuth, requireAdmin, async (req, res) => {
  const { username, password } = req.body;
  const db = loadDB();
  
  const newUser = {
    id: Math.max(...db.users.map(u => u.id), 0) + 1,
    username,
    password: await hashPassword(password),
    role: 'developer',
    createdAt: new Date().toISOString()
  };
  
  db.users.push(newUser);
  saveDB(db);
  
  res.redirect('/admin/user');
});

app.post('/admin/user/update/:id', requireAuth, requireAdmin, async (req, res) => {
  const { username, password } = req.body;
  const db = loadDB();
  const userId = parseInt(req.params.id);
  const userIndex = db.users.findIndex(u => u.id === userId);
  
  if (userIndex === -1) {
    return res.status(404).send('User not found');
  }
  
  db.users[userIndex].username = username;
  if (password && password.trim() !== '') {
    db.users[userIndex].password = await hashPassword(password);
  }
  
  saveDB(db);
  res.redirect('/admin/user');
});


app.get('/admin/code', requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  res.render('admin/repositories', { 
    user: req.session.user, 
    repositories: db.repositories 
  });
});

app.get('/admin/code/info/:id', requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  const repoId = parseInt(req.params.id);
  const repository = db.repositories.find(r => r.id === repoId);
  
  if (!repository) {
    return res.status(404).send('Repository not found');
  }
  
  const repoPath = path.join(__dirname, 'uploads', repoId.toString());
  let files = [];
  
  if (fs.existsSync(repoPath)) {
    files = fs.readdirSync(repoPath).map(file => {
      const filePath = path.join(repoPath, file);
      const stats = fs.statSync(filePath);
      return {
        name: file,
        isDirectory: stats.isDirectory(),
        size: stats.size,
        modified: stats.mtime
      };
    });
  }
  
  res.render('admin/repository-info', { 
    user: req.session.user, 
    repository,
    files,
    currentPath: ''
  });
});

