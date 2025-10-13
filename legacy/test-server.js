const express = require('express');
const app = express();
const PORT = 3000;

console.log('Creating Express app...');

app.get('/', (req, res) => {
  res.json({ message: 'Server is working!' });
});

console.log('Setting up routes...');

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

console.log('Server setup complete');
