
const express = require('express');
const axios = require('axios');

const app = express();

app.post('/upload', (req, res) => {
  const file = req.files.file;
  const accessToken = 'YOUR_ACCESS_TOKEN';

  const options = {
    method: 'POST',
    url: `https://graph.microsoft.com/v1.0/me/drive/items/${file.name}/content`,
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': file.mimetype
    },
    data: file.buffer
  };

  axios(options)
    .then(response => {
      res.send(`File uploaded successfully!`);
    })
    .catch(error => {
      res.status(500).send(`Error uploading file: ${error.message}`);
    });
});

app.listen(8080, () => {
  console.log('Server listening on port 8080');
});
