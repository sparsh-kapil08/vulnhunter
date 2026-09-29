import { Router } from 'express';
import { getHealth } from '../controllers/healthController.js';
import { addMessage, createSession, getSession, listSessions } from '../store.js';
import { answerChat } from '../orchestrator.js';
import { normalizeAttachments } from '../uploads.js';

const router = Router();

function readAttachments(value, res) {
	try {
		return normalizeAttachments(value);
	} catch (error) {
		res.status(400).json({ error: error.message });
		return undefined;
	}
}

// Starter health check route
router.get('/health', getHealth);

router.get('/sessions', (req, res) => res.json(listSessions()));

router.post('/sessions', async (req, res) => {
	const input = req.body || {};
	const attachments = readAttachments(input.attachments ?? input.attachment, res);
	if (attachments === undefined) return;
	const session = createSession(input);
	const content = String(input.challengeInput || '').trim();
	const userContent = content || (attachments.length ? `Please analyze the attached files ${attachments.map((file) => `"${file.name}"`).join(', ')} for security vulnerabilities and flag candidates.` : '');
	if (userContent) addMessage(session.id, { role: 'user', kind: 'chat', content: userContent, attachments });
	const emit = (message) => addMessage(session.id, message);
	if (userContent) await answerChat(userContent, emit, [], attachments);
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
	const attachments = readAttachments(req.body?.attachments ?? req.body?.attachment, res);
	if (attachments === undefined) return;
	const content = String(req.body?.content || '').trim();
	if (!content && !attachments.length) return res.status(400).json({ error: 'Message content or an attachment is required' });
	const userContent = content || `Please analyze the attached files ${attachments.map((file) => `"${file.name}"`).join(', ')} for security vulnerabilities and flag candidates.`;
	const previousMessages = session.messages.slice();
	addMessage(session.id, { role: 'user', kind: 'chat', content: userContent, attachments });
	await answerChat(userContent, (message) => addMessage(session.id, message), previousMessages, attachments);
	res.json(getSession(session.id));
});

export default router;
