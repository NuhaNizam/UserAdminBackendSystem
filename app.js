const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const auth = require('./middleware/auth');
const User = require('./Models/User');
const Assignment = require('./Models/Assignment');

dotenv.config();

const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Could not connect to MongoDB', err));

// Register User/Admin
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword, role });
    await user.save();
    res.status(201).send({ message: 'User created successfully' });
  } catch (error) {
    res.status(400).send({ error: 'Registration failed' });
  }
});

// Login User/Admin
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).send({ error: 'Invalid username or password' });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(400).send({ error: 'Invalid username or password' });

    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.send({ token,message : "Login Successed" });
  } catch (error) {
    res.status(500).send({ error: 'Login failed' });
  }
});

// Upload Assignment (Users Only)
app.post('/upload', auth, async (req, res) => {
  const { task, adminId } = req.body;
  if (req.user.role !== 'user') return res.status(403).send({ error: 'Access denied' });

  try {
    const assignment = new Assignment({
      userId: req.user.userId,
      task,
      adminId,
    });
    await assignment.save();
    res.status(201).send({ message: 'Assignment uploaded successfully' });
  } catch (error) {
    res.status(400).send({ error: 'Assignment upload failed' });
  }
});

// Get all Admins
app.get('/admins', async (req, res) => {
  try {
    const admins = await User.find({ role: 'admin' }).select('username');
    res.send(admins);
  } catch (error) {
    res.status(500).send({ error: 'Fetching admins failed' });
  }
});

// View Assignments (Admins Only)
app.get('/assignments', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send({ error: 'Access denied' });

  try {
    const assignments = await Assignment.find({ adminId: req.user.userId }).populate('userId', 'username');
    res.send(assignments);
  } catch (error) {
    res.status(500).send({ error: 'Fetching assignments failed' });
  }
});

// Accept Assignment (Admins Only)
app.post('/assignments/:id/accept', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send({ error: 'Access denied' });

  try {
    const assignment = await Assignment.findByIdAndUpdate(req.params.id, { status: 'accepted' }, { new: true });
    if (!assignment) return res.status(404).send({ error: 'Assignment not found' });
    res.send({ message: 'Assignment accepted', assignment });
  } catch (error) {
    res.status(500).send({ error: 'Failed to accept assignment' });
  }
});

// Reject Assignment (Admins Only)
app.post('/assignments/:id/reject', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send({ error: 'Access denied' });

  try {
    const assignment = await Assignment.findByIdAndUpdate(req.params.id, { status: 'rejected' }, { new: true });
    if (!assignment) return res.status(404).send({ error: 'Assignment not found' });
    res.send({ message: 'Assignment rejected', assignment });
  } catch (error) {
    res.status(500).send({ error: 'Failed to reject assignment' });
  }
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
