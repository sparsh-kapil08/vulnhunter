import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import apiRoutes from './routes/apiRoutes.js';
import { connectDB } from './config/db.js';

const serverDir = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: process.env.DOTENV_CONFIG_PATH || path.resolve(serverDir, '../.env') });

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({ origin: '*' }));
app.options('*', cors({ origin: '*' }));
app.use(express.json({ limit: '5mb' }));

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
  const server = app.listen(PORT, () => {
    console.log(`[Server] Official hackathon backend listening at http://localhost:${PORT}`);
    console.log(`[Server] Health check available at http://localhost:${PORT}/api/health`);
  });
  server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
      console.error(`[Server] Port ${PORT} is already in use. The existing VulnHunter server can be used at http://localhost:${PORT}.`);
      process.exit(0);
    }
    console.error('[Server] Could not start:', error.message);
    process.exit(1);
  });
}

export { app };
export default app;

if (!process.env.VERCEL) startServer();
