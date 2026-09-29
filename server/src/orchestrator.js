import { fetchAuthorizedUrl, probeTcpService, searchSource, inspectWebSurface, inspectBinary, craftPayload } from './tools.js';
import { askGemini } from './gemini.js';

export function looksLikeUrl(value = '') {
  return /^https?:\/\/\S+$/i.test(value.trim());
}

export function extractUrl(value = '') {
  const match = value.match(/https?:\/\/[^\s<>'"`]+/i);
  return match ? match[0].replace(/[),.;!?]+$/, '') : null;
}

function formatHistory(history = [], currentContent = '') {
  const current = (currentContent || '').trim();
  const lines = history
    .filter((message) => message.content && message.content.trim() !== current)
    .slice(-24)
    .map((message) => `${message.role}${message.kind ? ` (${message.kind})` : ''}: ${message.content}`);
  return lines.length ? lines.join('\n') : '(no earlier messages)';
}

export function looksLikeChallengeEvidence(value = '') {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 20000) return false;
  if (looksLikeUrl(trimmed)) return true;
  if (parseServiceTarget(trimmed)) return true;

  const challengeSignals = [
    /\b(?:nc|netcat|connect\s+to|service|banner|host|port|ssh|curl|wget)\b/i,
    /\b(?:flag|password|secret|challenge|ctf|vulnerab|exploit|target)\b/i,
    /\b(?:connect|telnet|socket|listen|probe)\b.*\b(?:host|port|target)\b/i,
    /\b(?:get\s+the\s+flag|find\s+the\s+flag|read\s+the\s+flag)\b/i,
    /\b(?:chatelaine|cylabacademy|localhost|127\.0\.0\.1)\b/i
  ];

  if (challengeSignals.some((pattern) => pattern.test(trimmed))) {
    return true;
  }

  if (/\b(?:eval|exec|execFile|spawn|SELECT\s+|innerHTML|child_process|system\s*\(|fetch\s*\(|axios|curl|wget)\b/i.test(trimmed)) {
    return true;
  }
  if (trimmed.includes('\n') && /(?:flag|password|secret|error|output|stdin|stdout|stderr)/i.test(trimmed)) {
    return true;
  }
  if (/\{[A-Za-z0-9_:-]+\}/.test(trimmed) || /\b[A-Za-z0-9._-]+\s*:\s*\d{1,5}\b/.test(trimmed)) {
    return true;
  }
  return false;
}

function parseServiceTarget(value = '') {
  const match = value.match(/(?:\bnc(?:\s+-[^\s]+)*|\bconnect(?:\s+to)?|\bhost)\s+(?:https?:\/\/)?([a-z0-9.-]+)(?:\s+(?:at\s+)?(?:port\s+)?|\s*:)\s*(\d{1,5})\b/i) || value.match(/\b([a-z0-9.-]+)\s*:\s*(\d{1,5})\b/i);
  return match && Number(match[2]) <= 65535 ? { host: match[1], port: Number(match[2]) } : null;
}

function decodeNumericBanner(value = '') {
  const tokens = value.trim().split(/\s+/);
  if (tokens.length < 2 || !tokens.every((token) => /^\d{1,3}$/.test(token) && Number(token) <= 255)) return value;
  return tokens.map((token) => String.fromCharCode(Number(token))).join('');
}

export function buildGeneralChatReply(content = '') {
  const text = (content || '').trim();
  if (!text) return 'I am here to assist you with authorized security analysis, CTF evidence examination, or general technical questions. How can I help?';
  return `I have analyzed your query: "${text}". Please provide any relevant context, source code, binary paths, or service information so I can assist you further.`;
}

function localChatReply(content, scan) {
  if (scan.matches.length) {
    const evidence = scan.matches.slice(0, 3).map((match) => `line ${match.line}: ${match.reason}`).join('; ');
    return `Static analysis detected ${scan.matches.length} pattern(s): ${evidence}. Please provide target artifacts or service details to analyze this further.`;
  }
  return buildGeneralChatReply(content);
}

export async function answerChat(content, onMessage, history = []) {
  const emit = (message) => onMessage({ role: message.role, ...message });
  const normalized = (content || '').trim();
  const url = extractUrl(normalized);
  const serviceTarget = parseServiceTarget(normalized);
  const conversationHistory = formatHistory(history, normalized);

  if (!url) {
    const isChallenge = looksLikeChallengeEvidence(normalized) || Boolean(serviceTarget);
    if (!isChallenge) {
      const directReply = await askGemini(`You are a conversational assistant. Answer the user normally and helpfully based on their actual question. Do not rely on fixed keyword patterns. Treat this as a general chat request unless the user provides actual challenge evidence such as a URL, source snippet, binary path, or target and port.\n\nPrevious conversation:\n${conversationHistory}\n\nCurrent user message:\n${normalized}`);
      const answer = directReply && directReply.trim() ? directReply : buildGeneralChatReply(normalized);
      emit({ role: 'agent', kind: 'chat', content: answer });
      return;
    }
    if (serviceTarget) {
      emit({ role: 'agent', kind: 'hypothesis', content: `I detected an authorized service target at ${serviceTarget.host}:${serviceTarget.port}. I will connect read-only, collect its process output, and search it for flag-shaped evidence.` });
      emit({ role: 'agent', kind: 'tool_call', toolName: 'probe_tcp_service', content: 'Reading the service banner with a 5-second timeout.' });
      const probe = await probeTcpService(serviceTarget.host, serviceTarget.port);
      const banner = probe.ok ? decodeNumericBanner(probe.banner) : '';
      const analyzedProbe = { ...probe, banner, rawBanner: probe.banner };
      emit({ role: 'tool', kind: 'tool_result', toolName: 'probe_tcp_service', toolResult: analyzedProbe, content: probe.ok ? banner : probe.error });
      const flag = banner.match(/[A-Za-z0-9_-]+\{[^}\n]{1,200}\}/)?.[0];
      const positiveFlagLine = banner.split(/\r?\n/).map((line) => line.trim()).find((line) => /\bflag\b/i.test(line) && !(/\bnot\b/i.test(line) || /\b(?:don't|dont)\b/i.test(line)));
      const flagEvidence = flag || positiveFlagLine;
      const reply = await askGemini(`You are reasoning on an authorized CTF service. Listen to the user's exact wording and the target details first. Do not stop at the first banner or the first failed hypothesis. If the output is noisy, encoded, or contains decoys, search for alternate evidence, hidden data, repeated clues, or a safe follow-up interaction requirement.\n\nPrevious conversation:\n${conversationHistory}\n\nCurrent user request / context:\n${content}\n\nTarget: ${serviceTarget.host}:${serviceTarget.port}\nObserved output:\n${banner || probe.error}\n\nImportant: We are not exploiting anything. We are gathering evidence and looking for safe, authorized next steps. If this first read is not conclusive, explain what alternative evidence path should be tried next.`);
      emit({ role: 'agent', kind: 'chat', content: reply || (probe.ok ? `I connected to ${serviceTarget.host}:${serviceTarget.port} and captured the process output.\n\n${flagEvidence ? `Flag candidate found: ${flagEvidence}` : 'No positive flag line was found in the captured output.'}\n\nI did not send a payload.` : `I could not read ${serviceTarget.host}:${serviceTarget.port}: ${probe.error}`) });
      return;
    }
    const localScan = searchSource(content);
    if (localScan.matches.length) {
      emit({ role: 'agent', kind: 'tool_call', toolName: 'search_source', content: 'Scanning the pasted snippet for input-to-sink patterns.' });
      emit({ role: 'tool', kind: 'tool_result', toolName: 'search_source', toolResult: localScan, content: JSON.stringify(localScan) });
    }
    const reply = await askGemini(`Respond as a helpful general assistant. If the user is simply asking a question, answer directly. Only do security analysis when the user provides a real challenge artifact such as a URL, source snippet, binary path, or service target.\n\nPrevious conversation:\n${conversationHistory}\n\nCurrent user message:\n${content}\n\nLocal scanner result:\n${JSON.stringify(localScan)}`);
    emit({ role: 'agent', kind: 'chat', content: reply || localChatReply(content, localScan) });
    return;
  }
  emit({ role: 'agent', kind: 'hypothesis', content: `I found a URL. I will retrieve its public challenge page, extract visible clues, and scan the response for leads.` });
  emit({ role: 'agent', kind: 'tool_call', toolName: 'fetch_authorized_url', content: 'Fetching the URL with an 8-second timeout and private-network protection.' });
  const fetched = await fetchAuthorizedUrl(url);
  emit({ role: 'tool', kind: 'tool_result', toolName: 'fetch_authorized_url', toolResult: { ...fetched, text: undefined }, content: fetched.ok ? `Fetched ${fetched.status} ${fetched.contentType || ''} from ${fetched.url}` : fetched.error });
  if (!fetched.ok) {
    emit({ role: 'agent', kind: 'chat', content: `I could not retrieve that URL: ${fetched.error} Try pasting the challenge text, source, or netcat output here.` });
    return;
  }
  const result = searchSource(fetched.text);
  const webSurface = inspectWebSurface(fetched.text, fetched.url);
  emit({ role: 'agent', kind: 'tool_call', toolName: 'inspect_web_surface', content: 'Inspecting forms, scripts, links, and query parameters for web-application leads.' });
  emit({ role: 'tool', kind: 'tool_result', toolName: 'inspect_web_surface', toolResult: webSurface, content: JSON.stringify(webSurface) });
  const clues = fetched.text.match(/(?:flag|password|secret|nc\s+[^<\s]+|ssh\s+[^<\s]+)/gi)?.slice(0, 8) || [];
  const localReply = result.matches.length
    ? `I retrieved the page and found ${result.matches.length} suspicious code pattern(s). The strongest lead is on line ${result.matches[0].line}: ${result.matches[0].reason} Paste the netcat banner or downloadable source next so I can validate it in the sandbox.`
    : `I retrieved the page, but it does not expose source-level vulnerability patterns. Visible leads: ${clues.length ? clues.join(', ') : 'none obvious'}. Paste the challenge output or attach the downloaded source/binary for deeper analysis.`;
  const reply = await askGemini(`Treat this as a real investigation, not a static summary. Listen to the user’s challenge wording and follow the strongest evidence. If the page looks like a decoy or the first clue is weak, think of alternative routes: hidden encoded data, challenge type hints, command examples, or a second artifact to inspect.\n\nPrevious conversation:\n${conversationHistory}\n\nCurrent user request:\n${content}\n\nURL: ${fetched.url}\nWeb surface evidence: ${JSON.stringify(webSurface)}\nLocal scanner result: ${JSON.stringify(result)}\nPage excerpt:\n${fetched.text}\n\nDo not claim exploitation. Identify the likely challenge category, the strongest clue, and the next safe evidence to collect if the first idea does not pan out. For forms, parameters, scripts, or suspicious sinks, explain what could be tested only against an authorized target.`) || localReply;
  emit({ role: 'agent', kind: 'chat', content: reply });
}

export async function investigate(input, onMessage) {
  const emit = (message) => onMessage({ role: message.role, ...message });
  emit({ role: 'agent', kind: 'hypothesis', content: 'I will scan the supplied challenge for common input-to-sink patterns.' });

  let result;
  if (input.sourceType === 'binary') {
    emit({ role: 'agent', kind: 'tool_call', toolName: 'inspect_binary', content: 'Inspecting binary protections and readable strings.' });
    result = await inspectBinary(input.challengeInput);
  } else {
    emit({ role: 'agent', kind: 'tool_call', toolName: 'search_source', content: 'Scanning source with local pattern checks.' });
    result = searchSource(input.challengeInput);
  }
  emit({ role: 'tool', kind: 'tool_result', toolName: result.tool, toolResult: result, content: JSON.stringify(result) });

  const firstMatch = result.matches?.[0];
  const vulnClass = firstMatch?.reason.includes('SQL') ? 'sqli' : firstMatch?.reason.includes('HTML') ? 'xss' : firstMatch ? 'command_injection' : 'none_detected';
  const evidence = firstMatch ? `Line ${firstMatch.line}: ${firstMatch.code}` : 'No matching dangerous sink was found in the supplied input.';
  if (vulnClass !== 'none_detected') {
    const payload = craftPayload(vulnClass);
    emit({ role: 'agent', kind: 'tool_call', toolName: 'craft_payload', content: `Preparing a harmless proof-of-concept for ${vulnClass}.` });
    emit({ role: 'tool', kind: 'tool_result', toolName: 'craft_payload', toolResult: payload, content: JSON.stringify(payload) });
  }
  const verdict = { vulnClass, evidence, exploitPath: vulnClass === 'none_detected' ? 'No exploit path identified.' : `Validate the sink at ${evidence} inside the authorized sandbox.`, confidence: firstMatch ? 0.82 : 0.35 };
  emit({ role: 'agent', kind: 'verdict', content: JSON.stringify(verdict), verdict });
  return verdict;
}