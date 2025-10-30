// Required Modules
require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/chatApp', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB Error:', err));

// Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  online: { type: Boolean, default: false },
  lastSeen: { type: Date }
});
const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  room: { type: String },
  content: { type: String },
  isFile: { type: Boolean, default: false },
  fileUrl: { type: String },
  timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer Setup
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = path.join(__dirname, 'uploads');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir);
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
    }
  })
});

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'chat.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    await new User({ username, password: hashed }).save();
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ userId: user._id }, 'your-secret-key', { expiresIn: '1h' });
    user.online = true;
    await user.save();

    res.json({ token, username: user.username, userId: user._id });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/users', async (req, res) => {
  const users = await User.find({}, 'username online');
  res.json(users);
});

app.get('/api/messages', async (req, res) => {
  const { userId, room } = req.query;
  let messages = [];

  if (userId && mongoose.Types.ObjectId.isValid(userId)) {
    messages = await Message.find({
      $or: [{ sender: userId }, { receiver: userId }]
    }).populate('sender receiver');
  } else if (room) {
    messages = await Message.find({ room }).populate('sender');
  }

  res.json(messages);
});

app.post('/api/upload', upload.single('file'), (req, res) => {
  res.json({ url: `/uploads/${req.file.filename}` });
});

// Socket.IO Auth Middleware
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    const decoded = jwt.verify(token, 'your-secret-key');
    const user = await User.findById(decoded.userId);
    if (!user) throw new Error('Auth failed');
    socket.user = user;
    next();
  } catch (err) {
    next(new Error('Authentication failed'));
  }
});

// Socket.IO Events
io.on('connection', (socket) => {
  const user = socket.user;
  console.log(`🔗 ${user.username} connected`);

  socket.on('joinRoom', async (room) => {
    const socketsInRoom = await io.in(room).allSockets();
    if (socketsInRoom.size >= 1) {
      socket.emit('roomFull', room);
      return;
    }
    socket.join(room);
    console.log(`📥 ${user.username} joined room: ${room}`);
  });

  socket.on('privateMessage', async (msg) => {
    if (!mongoose.Types.ObjectId.isValid(msg.receiverId)) return;
    const message = new Message({
      sender: user._id,
      receiver: msg.receiverId,
      content: msg.content,
      timestamp: new Date()
    });
    await message.save();

    const targetSocket = [...io.sockets.sockets.values()].find(
      s => s.user?._id.toString() === msg.receiverId
    );
    if (targetSocket) {
      targetSocket.emit('privateMessage', {
        ...msg,
        sender: { _id: user._id, username: user.username },
        timestamp: message.timestamp
      });
    }
  });

  socket.on('roomMessage', async (msg) => {
    const message = new Message({
      sender: user._id,
      room: msg.room,
      content: msg.content,
      timestamp: new Date()
    });
    await message.save();

    io.to(msg.room).emit('roomMessage', {
      ...msg,
      sender: { _id: user._id, username: user.username },
      timestamp: message.timestamp
    });
  });

  socket.on('fileMessage', async (msg) => {
    const messageData = {
      sender: user._id,
      isFile: true,
      fileUrl: msg.fileUrl,
      timestamp: new Date()
    };

    if (msg.room) {
      messageData.room = msg.room;
    } else if (msg.receiverId && mongoose.Types.ObjectId.isValid(msg.receiverId)) {
      messageData.receiver = msg.receiverId;
    } else {
      console.warn('❌ Invalid receiver ID:', msg.receiverId);
      return;
    }

    const message = new Message(messageData);
    await message.save();

    const payload = {
      ...msg,
      sender: { _id: user._id, username: user.username },
      timestamp: message.timestamp
    };

    if (msg.room) {
      io.to(msg.room).emit('fileMessage', payload);
    } else {
      const targetSocket = [...io.sockets.sockets.values()].find(
        s => s.user?._id.toString() === msg.receiverId
      );
      if (targetSocket) {
        targetSocket.emit('fileMessage', payload);
      }
    }
  });

  socket.on('disconnect', async () => {
    await User.findByIdAndUpdate(user._id, { online: false, lastSeen: new Date() });
    console.log(`❌ ${user.username} disconnected`);
  });
});

const PORT = 3010;
server.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
