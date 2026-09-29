import { Router } from 'express';

const router = Router();

router.post('/register', (req, res) => {
  res.status(200).json({ message: 'User registration endpoint skeleton' });
});

router.post('/login', (req, res) => {
  res.status(200).json({ message: 'User login endpoint skeleton' });
});

export default router;
