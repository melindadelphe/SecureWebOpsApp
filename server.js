import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import pdfRoutes from './routes/pdfRoutes.js'; // Note the .js at the end

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Routes
app.use('/api/pdf', pdfRoutes);

app.get('/', (req, res) => res.send('SecureWebOps Backend is Running Securely'));

app.listen(PORT, () => {
    console.log(`[SUCCESS] Server started on port ${PORT}`);
});