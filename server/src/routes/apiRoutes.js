import { Router } from 'express';
import { getHealth } from '../controllers/healthController.js';
import { addMessage, createSession, getSession, listSessions } from '../store.js';
import { answerChat } from '../orchestrator.js';

const router = Router();

// Starter health check route
router.get('/health', getHealth);

router.get('/sessions', (req, res) => res.json(listSessions()));

router.post('/sessions', async (req, res) => {
	const input = req.body || {};
	const session = createSession(input);
	const content = String(input.challengeInput || '').trim();
	if (content) addMessage(session.id, { role: 'user', kind: 'chat', content });
	const emit = (message) => addMessage(session.id, message);
	await answerChat(content, emit);
	res.status(201).json({ sessionId: session.id, session: getSession(session.id) });
});

router.get('/sessions/:id', (req, res) => {
	const session = getSession(req.params.id);
	if (!session) return res.status(404).json({ error: 'Session not found' });
	res.json(session);
});

router.post('/sessions/:id/message', async (req, res) => {
	const session = getSession(req.params.id);
	if (!session) return res.status(404).json({ error: 'Session not found' });
	const content = String(req.body?.content || '').trim();
	if (!content) return res.status(400).json({ error: 'Message content is required' });
	const previousMessages = session.messages.slice();
	addMessage(session.id, { role: 'user', kind: 'chat', content });
	await answerChat(content, (message) => addMessage(session.id, message), previousMessages);
	res.json(getSession(session.id));
});

export default router;
