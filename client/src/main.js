const app = document.querySelector('#app');
const isLocal = ['localhost', '127.0.0.1', '::1'].includes(window.location.hostname);
const defaultApi = isLocal ? `${window.location.protocol}//${window.location.hostname}:5000/api` : 'https://server-ashen-eight.vercel.app/api';
const API = (import.meta.env.VITE_API_URL || defaultApi).replace(/\/$/, '');
let currentSession = null;

app.innerHTML = `
  <main class="app-shell">
    <aside class="sidebar">
      <header class="side-header"><a class="brand" href="#"><span class="brand-mark">VH</span><strong>VulnHunter</strong></a><button id="new-chat" class="icon-button" title="New chat">+</button></header>
      <button id="start-chat" class="new-chat">+ New investigation</button>
      <div class="history-heading"><span>INVESTIGATION HISTORY</span><button id="refresh-history" title="Refresh history">↻</button></div>
      <nav id="history" class="history"><div class="history-empty">No investigations yet.</div></nav>
      <div class="side-footer"><span class="status-dot"></span><span>Local sandbox ready</span></div>
    </aside>
    <section class="chat-shell">
      <header class="chat-header"><div><p class="eyebrow">AUTHORIZED SECURITY RESEARCH</p><h1 id="chat-title">New investigation</h1></div><span id="connection" class="connection"><i></i> CHECKING BACKEND</span></header>
      <div id="messages" class="messages"><div class="welcome"><div class="welcome-mark">VH</div><h2>What are you investigating?</h2><p>Send a CTF link, netcat output, source code, or a question. I will keep the conversation and evidence together.</p><div class="suggestions"><button data-prompt="https://play.picoctf.org/">Analyze a picoCTF URL</button><button data-prompt="I have a netcat challenge. What output should I share?">Help with netcat output</button><button data-prompt="I found suspicious input reaching a shell command.">Review a vulnerability lead</button></div></div></div>
      <form id="composer" class="composer"><textarea id="message-input" rows="1" placeholder="Message VulnHunter... Paste a public CTF URL or challenge output" autocomplete="off"></textarea><label class="attach-button" title="Attach up to three files" aria-label="Attach up to three files">＋<input id="file-input" type="file" multiple></label><button type="submit" title="Send message">↑</button><small id="composer-hint">Authorized targets only · Enter to send · Shift+Enter for a new line</small><small id="attachment-name" class="attachment-name" hidden></small></form>
    </section>
  </main>
  <div id="toast" class="toast"></div>
`;

const messages = document.querySelector('#messages');
const input = document.querySelector('#message-input');
const fileInput = document.querySelector('#file-input');
const history = document.querySelector('#history');
const title = document.querySelector('#chat-title');
let selectedFiles = [];

function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[character])); }
function showToast(message) { const toast = document.querySelector('#toast'); toast.textContent = message; toast.classList.add('visible'); setTimeout(() => toast.classList.remove('visible'), 2800); }
function printableStrings(bytes) {
  const strings = [];
  let current = '';
  for (const byte of bytes) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) current += String.fromCharCode(byte);
    else if (current.length >= 4) { strings.push(current); current = ''; }
    else current = '';
  }
  if (current.length >= 4) strings.push(current);
  return strings.join('\n');
}
async function readAttachment(file) {
  if (file.size > 256 * 1024) throw new Error(`"${file.name}" is larger than 256 KB.`);
  const bytes = new Uint8Array(await file.arrayBuffer());
  let content;
  try { content = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch {}
  if (content === undefined || content.includes('\0')) content = printableStrings(bytes);
  return { name: file.name, content };
}
function renderMarkdown(value) {
  return value
    .replace(/^#{1,6}\s+(.+)$/gm, '<strong>$1</strong>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`\n]+)`/g, '<code>$1</code>');
}
function formatContent(message) {
  if (message.kind === 'tool_result') return `<pre>${escapeHtml(message.content || JSON.stringify(message.toolResult, null, 2))}</pre>`;
  const escapedContent = escapeHtml(message.content || '');
  const content = message.role === 'agent' ? renderMarkdown(escapedContent) : escapedContent;
  const attachments = message.attachments || (message.attachment ? [message.attachment] : []);
  if (!attachments.length) return content;
  return `${content}${attachments.map((attachment) => `<details class="attachment-preview"><summary>${escapeHtml(attachment.name)}${attachment.truncated ? ' · excerpt' : ''}</summary><pre>${escapeHtml(attachment.content)}</pre></details>`).join('')}`;
}
function messageLabel(message) { return message.role === 'user' ? 'You' : message.kind === 'tool_call' ? `Tool · ${message.toolName}` : message.kind === 'hypothesis' ? 'Agent reasoning' : message.kind === 'verdict' ? 'Verdict' : message.role === 'tool' ? 'Tool result' : 'VulnHunter'; }
function renderMessages(session) {
  currentSession = session;
  title.textContent = session.challengeName || 'Investigation';
  const visible = session.messages.filter((message) => message.kind !== 'hypothesis' || message.role === 'agent');
  messages.innerHTML = visible.length ? visible.map((message) => `<article class="message ${message.role} ${message.kind || ''}"><div class="avatar">${message.role === 'user' ? 'YO' : 'VH'}</div><div class="message-body"><div class="message-meta"><b>${messageLabel(message)}</b><time>${new Date(message.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</time></div><div class="message-content">${formatContent(message)}${message.verdict ? `<div class="verdict-inline"><span>DETECTED</span><strong>${escapeHtml(message.verdict.vulnClass.replaceAll('_', ' '))}</strong><small>${Math.round(message.verdict.confidence * 100)}% confidence · ${escapeHtml(message.verdict.evidence)}</small></div>` : ''}</div></div></article>`).join('') : document.querySelector('.welcome').outerHTML;
  messages.scrollTop = messages.scrollHeight;
}
function renderHistory(items) {
  history.innerHTML = items.length ? items.map((item) => `<button class="history-item ${currentSession?.id === item.id ? 'active' : ''}" data-id="${item.id}"><span class="history-icon">⌁</span><span><b>${escapeHtml(item.challengeName || 'Untitled investigation')}</b><small>${new Date(item.createdAt).toLocaleDateString()}</small></span></button>`).join('') : '<div class="history-empty">No investigations yet.</div>';
  history.querySelectorAll('[data-id]').forEach((button) => button.addEventListener('click', () => loadSession(button.dataset.id)));
}
async function loadHistory() { try { const response = await fetch(`${API}/sessions`); if (response.ok) renderHistory(await response.json()); } catch { showToast('API is offline. Check the configured backend URL.'); } }
async function checkBackend() {
  const status = document.querySelector('#connection');
  try {
    const response = await fetch(`${API}/health`);
    status.innerHTML = response.ok ? '<i></i> BACKEND ONLINE' : '<i></i> BACKEND ERROR';
    status.classList.toggle('offline', !response.ok);
  } catch {
    status.innerHTML = '<i></i> BACKEND OFFLINE';
    status.classList.add('offline');
  }
}
async function loadSession(id) { const response = await fetch(`${API}/sessions/${id}`); if (response.ok) { renderMessages(await response.json()); await loadHistory(); } }
function clearAttachment() { selectedFiles = []; fileInput.value = ''; document.querySelector('#attachment-name').hidden = true; document.querySelector('#composer-hint').hidden = false; }
function newChat() { currentSession = null; title.textContent = 'New investigation'; renderMessages({ messages: [] }); clearAttachment(); input.focus(); renderHistory([]); }
function showThinking() {
  messages.insertAdjacentHTML('beforeend', '<article id="thinking" class="message agent thinking"><div class="avatar">VH</div><div class="message-body"><div class="message-meta"><b>VulnHunter</b><span>thinking</span></div><div class="thinking-dots"><i></i><i></i><i></i></div></div></article>');
  messages.scrollTop = messages.scrollHeight;
}
async function sendMessage(content) {
  if (!content.trim() && !selectedFiles.length) return;
  let attachments = [];
  if (selectedFiles.length) {
    try {
      attachments = await Promise.all(selectedFiles.map(readAttachment));
    } catch (error) {
      showToast(error.message || 'Could not read the selected file.');
      return;
    }
  }
  const userContent = content.trim() || `Please analyze ${attachments.length === 1 ? 'the attached file' : 'the attached files'} ${attachments.map((attachment) => `"${attachment.name}"`).join(', ')} for security vulnerabilities and flag candidates.`;
  input.value = '';
  const existingSession = currentSession;
  const pendingMessage = { role: 'user', kind: 'chat', content: userContent, attachments, createdAt: new Date().toISOString() };
  const pendingSession = existingSession
    ? { ...existingSession, messages: [...existingSession.messages, pendingMessage] }
    : { challengeName: userContent.startsWith('http') ? 'URL investigation' : 'New investigation', messages: [pendingMessage] };
  renderMessages(pendingSession);
  showThinking();
  document.querySelector('.composer button').disabled = true;
  document.querySelector('.attach-button').classList.add('disabled');
  try {
    let session;
    if (!existingSession) {
      const response = await fetch(`${API}/sessions`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeName: userContent.startsWith('http') ? 'URL investigation' : 'New investigation', sourceType: 'source', challengeInput: content, attachments }) });
      if (!response.ok) throw new Error('Could not start investigation');
      session = (await response.json()).session;
    } else {
      const response = await fetch(`${API}/sessions/${existingSession.id}/message`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content, attachments }) });
      if (!response.ok) throw new Error('Could not send message');
      session = await response.json();
    }
    renderMessages(session); clearAttachment(); await loadHistory();
  } catch (error) {
    document.querySelector('#thinking')?.remove();
    console.error('[Chat] Request failed:', error);
    showToast(`Could not complete this message: ${error.message}`);
  } finally { document.querySelector('.composer button').disabled = false; document.querySelector('.attach-button').classList.remove('disabled'); input.focus(); }
}
document.querySelector('#composer').addEventListener('submit', (event) => { event.preventDefault(); sendMessage(input.value); });
fileInput.addEventListener('change', () => {
  const files = [...(fileInput.files || [])];
  if (files.length > 3) {
    showToast('Select no more than three files.');
    clearAttachment();
    return;
  }
  selectedFiles = files;
  const name = document.querySelector('#attachment-name');
  name.textContent = selectedFiles.length ? `Attached: ${selectedFiles.map((file) => file.name).join(', ')}` : '';
  name.hidden = !selectedFiles.length;
  document.querySelector('#composer-hint').hidden = Boolean(selectedFiles.length);
});
input.addEventListener('keydown', (event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); sendMessage(input.value); } });
input.addEventListener('keyup', (event) => { if (event.key === 'Enter' && !event.shiftKey && input.value.trim()) { event.preventDefault(); sendMessage(input.value); } });
document.querySelector('#new-chat').addEventListener('click', newChat);
document.querySelector('#start-chat').addEventListener('click', newChat);
document.querySelector('#refresh-history').addEventListener('click', loadHistory);
document.querySelectorAll('[data-prompt]').forEach((button) => button.addEventListener('click', () => { input.value = button.dataset.prompt; input.focus(); }));
loadHistory();
checkBackend();
