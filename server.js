const express = require('express');
const mongoose = require('mongoose');
const config = require('./config/config');
const authRoutes = require('./routes/authRoutes');

const app = express();

app.use(express.json());

// Logging the MongoDB URI for debugging
console.log('MongoDB URI:', config.mongoURI);

mongoose.connect(config.mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

app.use('/api/auth', authRoutes);

// Basic route for root endpoint
app.get('/', (req, res) => {
  res.send('Welcome to the API!');
});

const port = config.port;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
