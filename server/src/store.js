import crypto from 'node:crypto';

const sessions = new Map();

function supabaseHeaders() {
  const key = process.env.SUPABASE_KEY;
  return key ? { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', Prefer: 'return=minimal' } : null;
}

async function supabaseInsert(table, row) {
  const headers = supabaseHeaders();
  if (!process.env.SUPABASE_URL || !headers) return;
  try {
    await fetch(`${process.env.SUPABASE_URL}/rest/v1/${table}`, { method: 'POST', headers, body: JSON.stringify(row) });
  } catch (error) {
    console.warn(`[Supabase] Could not persist ${table}: ${error.message}`);
  }
}

function id() {
  return crypto.randomUUID();
}

export function createSession(input) {
  const session = {
    id: id(),
    challengeName: input.challengeName || 'Untitled challenge',
    sourceType: input.sourceType || 'source',
    challengeInput: input.challengeInput || '',
    createdAt: new Date().toISOString(),
    messages: []
  };
  sessions.set(session.id, session);
  void supabaseInsert('sessions', { id: session.id, challenge_name: session.challengeName, source_type: session.sourceType, created_at: session.createdAt });
  return session;
}

export function getSession(sessionId) {
  return sessions.get(sessionId);
}

export function addMessage(sessionId, message) {
  const session = getSession(sessionId);
  if (!session) return null;
  const saved = { id: id(), createdAt: new Date().toISOString(), ...message };
  session.messages.push(saved);
  void supabaseInsert('messages', { id: saved.id, session_id: sessionId, role: saved.role, content: saved.content || null, tool_name: saved.toolName || null, tool_result: saved.toolResult || null, created_at: saved.createdAt });
  return saved;
}

export function listSessions() {
  return [...sessions.values()].map(({ messages, challengeInput, ...summary }) => summary);
}