import express from "express";
import jwt from "jsonwebtoken";
import session from "express-session";
import mongoose from "mongoose";
import env from "dotenv";
import path from "path";
import { fileURLToPath } from 'url';
import { dirname } from 'path';



env.config();
const app = express();
const PORT = process.env.PORT || 3000;
const sessionSecret = process.env.SESSION_SECRET;
const jwtSecret = process.env.JWT_SECRET;
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

mongoose.set('strictQuery', false);

const uri =  "mongodb://localhost:27017/socialMediaDB";
await mongoose.connect(uri).then(() => console.log("Database is connected"));

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    }, 
    email: {
        type: String,
        required: true,
        unique: true
    }, 
    password: {
        type: String,
        required: true
    }
});

const postSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User'
    }, 
    text: String
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ 
    secret: sessionSecret, 
    resave: false, 
    saveUninitialized: true, 
    cookie: {
        secure: false,
        httpOnly: true
    }
}));


// Insert your authenticateJWT Function code here.
function authenticateJWT(req, res, next) {
  // Get token from session
  const token = req.session.token;

  // If no token, return 401 Unauthorized
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  try {
    // Verify token
    const decoded = jwt.verify(token, jwtSecret);
    
    // Attach user data to request
    req.user = decoded;
    
    // Continue to the next middleware
    next();
  } catch (error) {
    // If invalid token, return 401
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// Insert your requireAuth Function code here.
function requireAuth(req, res, next) {
  const token = req.session.token;  // Retrieve token from session

  if (!token) return res.redirect('/login');  // If no token, redirect to login page

  try {
    const decoded = jwt.verify(token, jwtSecret);  // Verify the token using the secret key

    req.user = decoded;  // Attach decoded user data to the request

    next();  // Pass control to the next middleware/route

  } catch (error) {
    return res.redirect('/login');  // If token is invalid, redirect to login page
  }
}

// Insert your routing HTML code here.
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

app.get('/post', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'post.html')));

app.get('/index', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html'), { username: req.user.username }));


// Insert your user registration code here.
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Check if the user already exists
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });

    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    // Create and save the new user
    const newUser = new User({ username, email, password });
    await newUser.save();

    // Generate JWT token and store in session
    const token = jwt.sign({ userId: newUser._id, username: newUser.username }, jwtSecret, { expiresIn: '1h' });
    req.session.token = token;

    // Respond with success message
    res.redirect(`/index?username=${newUser.username}`);
  } catch (error) {
    console.error(error);
    // Handle server errors
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Insert your user login code here.
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if the user exists with the provided credentials
    const user = await User.findOne({ username, password });

    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    // Generate JWT token and store in session
    const token = jwt.sign({ userId: user._id, username: user.username }, jwtSecret, { expiresIn: '1h' });
    req.session.token = token;

    // Respond with a success message
    res.redirect(`/index?username=${user.username}`);
  } catch (error) {
    console.error(error);
    // Handle server errors
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Insert your post creation code here.
app.post('/post', authenticateJWT, async (req, res) => {
    const { text } = req.body;

    // Validate post content
    if (!text || typeof text !== 'string') {
        return res.status(400).json({ message: 'Please provide valid post content' });
    }

    try {
        // Create and save new post with userId
        const newPost = new Post({ userId: req.user.userId, text });
        await newPost.save();
        res.status(201).json({ message: 'Post created successfully', post: newPost });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Get all posts for the authenticated user
app.get('/posts', authenticateJWT, async (req, res) => {
    try {
        // Fetch posts for the logged-in user
        const posts = await Post.find({ userId: req.user.userId });
        res.json({ posts });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Insert your post updation code here.
app.put('/posts/:postId', authenticateJWT, async (req, res) => {
    const postId = req.params.postId;
    const { text } = req.body;

    try {
        // Find and update the post, ensuring it's owned by the authenticated user
        const post = await Post.findOneAndUpdate(
            { _id: postId, userId: req.user.userId },
            { text },
            { new: true } // Return updated post
        );

        // Return error if post not found
        if (!post) return res.status(404).json({ message: 'Post not found' });

        res.json({ message: 'Post updated successfully', updatedPost: post });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Insert your post deletion code here.
app.delete('/posts/:postId', authenticateJWT, async (req, res) => {
    const postId = req.params.postId;

    try {
        // Find and delete the post, ensuring it's owned by the authenticated user
        const post = await Post.findOneAndDelete({ _id: postId, userId: req.user.userId });

        // Return error if post not found
        if (!post) return res.status(404).json({ message: 'Post not found' });

        res.json({ message: 'Post deleted successfully', deletedPost: post });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Insert your user logout code here.
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error(err); // Log any session destruction errors
    res.redirect('/login'); // Redirect to login page after logout
  });
});

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
