const express = require('express');
const app = express();
const port = 3000;

const secret = process.env.SECRET_WORD || 'NotSet';

app.get('/', (req, res) => {
  res.send(`SECRET_WORD is: ${secret}`);
});

app.get('/docker', (req, res) => {
  res.send('Docker check passed!');
});

app.get('/loadbalanced', (req, res) => {
  res.send('Load Balancer check passed!');
});

app.get('/secret_word', (req, res) => {
  res.send(`SECRET_WORD is: ${secret}`);
});

app.get('/tls', (req, res) => {
  res.send('TLS check passed!');
});

app.listen(port, () => {
  console.log(`App running on port ${port}`);
});
