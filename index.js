const express = require('express');
const app = express();
const helmet = require('helmet');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const sharp = require('sharp');
const promClient = require('prom-client');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
require('dotenv').config(); // Load environment variables from .env file

// Ensure the uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// In-memory cache
const cache = {};

// Multer storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Dossier où les images seront stockées
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname); // Nom unique pour chaque image
  }
});

// File filter to validate image files
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, and GIF are allowed.'));
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter
});

// JWT secret key
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (ex) {
    res.status(400).json({ message: 'Invalid token.' });
  }
};

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

// Performance metrics
const collectDefaultMetrics = promClient.collectDefaultMetrics;
collectDefaultMetrics();

const httpRequestDurationMicroseconds = new promClient.Histogram({
  name: 'http_request_duration_ms',
  help: 'Duration of HTTP requests in ms',
  labelNames: ['method', 'route', 'code'],
  buckets: [50, 100, 200, 300, 400, 500, 1000] // buckets for response time from 50ms to 1000ms
});

app.use((req, res, next) => {
  const end = httpRequestDurationMicroseconds.startTimer();
  res.on('finish', () => {
    end({ method: req.method, route: req.route ? req.route.path : '', code: res.statusCode });
  });
  next();
});

// CORS configuration
const corsOptions = {
  origin: 'https://image-upload-client-nbj7p8zpy-aladdinbruvs-projects.vercel.app', // Update this to match the URL of your React app
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(helmet());
app.use(express.json());
app.use(limiter);

// Winston logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Middleware for logging requests
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.url}`);
  next();
});

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// MongoDB configuration
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const imageSchema = new mongoose.Schema({
  originalUrl: String,
  optimizedUrl: String,
  uploadDate: { type: Date, default: Date.now }
});

const Image = mongoose.model('Image', imageSchema);

app.post('/upload', authenticateJWT, upload.single('image'), async (req, res) => {
  try {
    const filePath = path.join(__dirname, 'uploads', req.file.filename);
    const optimizedPath = path.join(__dirname, 'uploads', 'optimized-' + req.file.filename);
    const format = req.body.format || 'jpeg'; // Default to 'jpeg' if no format is provided

    // Optimize the image
    await sharp(filePath)
      .resize(800, 800, { fit: 'inside' })
      .toFormat(format, { quality: 80 })
      .toFile(optimizedPath);

    // Upload original image to Cloudinary
    const originalImage = await cloudinary.uploader.upload(filePath, {
      folder: 'originals'
    });

    // Upload optimized image to Cloudinary
    const optimizedImage = await cloudinary.uploader.upload(optimizedPath, {
      folder: 'optimized'
    });

    // Save image metadata to MongoDB
    const image = new Image({
      originalUrl: originalImage.secure_url,
      optimizedUrl: optimizedImage.secure_url
    });
    await image.save();

    res.set('Cache-Control', 'public, max-age=31536000'); // Cache for 1 year
    res.json({
      originalUrl: originalImage.secure_url,
      optimizedUrl: optimizedImage.secure_url
    });
  } catch (error) {
    logger.error(error.stack);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/metrics', async (req, res) => {
  res.set('Content-Type', promClient.register.contentType);
  res.end(await promClient.register.metrics());
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Replace with your own user authentication logic
  if (username === 'user' && password === 'password') {
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ message: 'Invalid username or password' });
  }
});

// Serve a simple message for the root URL
app.get('/', (req, res) => {
  res.send('Welcome to the Image Upload Service');
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveur lancé sur le port ${PORT}`);
});