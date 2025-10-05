
const express = require('express');
const cors = require('cors');
const multer = require('multer');

const app = express();
const port = 3001;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer({ dest: 'uploads/' });

app.get('/', (req, res) => {
  res.send('SpeechParrot server is running!');
});

app.post('/transcribe', upload.single('audio'), (req, res) => {
  // For now, we'll just return mock data.
  // In a real application, you would process the audio file here.
  console.log('Received audio file:', req.file);

  const original_transcription = "This is the original transcription from the speech-to-text engine.";
  const corrected_transcription = "This is the corrected and grammatically improved transcription.";

  res.json({
    original_transcription,
    corrected_transcription,
  });
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
