import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import apiRoutes from './routes/apiRoutes.js';
import { connectDB } from './config/db.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Mount API routes
app.use('/api', apiRoutes);

// Root informational endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'Hackathon Starter API',
    message: 'Official hackathon boilerplate server active. See /api/health for system status.',
    docs: '/api/health'
  });
});

async function startServer() {
  await connectDB();
  app.listen(PORT, () => {
    console.log(`[Server] Official hackathon backend listening at http://localhost:${PORT}`);
    console.log(`[Server] Health check available at http://localhost:${PORT}/api/health`);
  });
}

startServer();
