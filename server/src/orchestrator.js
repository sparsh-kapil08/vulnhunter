import { fetchAuthorizedUrl, probeTcpService, searchSource, grepFiles, isBlockedHost, parseRsaParameters, decryptRsaChallenge, decryptRsaWithFactors, lookupRsaFactors, inspectWebSurface, inspectBinary, craftPayload } from './tools.js';
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
    .map((message) => `${message.role}${message.kind ? ` (${message.kind})` : ''}: ${message.content}${(message.attachments || (message.attachment ? [message.attachment] : [])).map((file) => `\nAttachment (${file.name}):\n${file.content}`).join('')}`);
  return lines.length ? lines.join('\n').slice(-8000) : '(no earlier messages)';
}

export function looksLikeChallengeEvidence(value = '') {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 20000) return false;
  if (parseRsaParameters(trimmed)) return true;
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

function isPythonChallengeRequest(value = '') {
  return /\b(?:run|execute|simulate|solve|analyze|analyse)\b/i.test(value) &&
    /\b(?:python|script|code)\b/i.test(value) &&
    /\b(?:flag|binary|decimal|challenge)\b/i.test(value);
}

function parseServiceTarget(value = '') {
  const match = value.match(/(?:\bnc(?:\s+-[^\s]+)*|\bconnect(?:\s+to)?|\bhost)\s+(?:https?:\/\/)?([a-z0-9.-]+)(?:\s+(?:at\s+)?(?:port\s+)?|\s*:)\s*(\d{1,5})\b/i) || value.match(/\b([a-z0-9.-]+)\s*:\s*(\d{1,5})\b/i);
  return match && Number(match[2]) <= 65535 ? { host: match[1], port: Number(match[2]) } : null;
}

export function parseTcpUrlTarget(value = '') {
  let parsed;
  try { parsed = new URL(value); } catch { return null; }
  if (!['http:', 'https:'].includes(parsed.protocol) || isBlockedHost(parsed.hostname)) return null;
  const explicitPort = parsed.port || value.match(/^https?:\/\/(?:[^/@]+@)?(?:\[[^\]]+\]|[^/:?#]+):(\d+)(?:[/?#]|$)/i)?.[1];
  const port = Number(explicitPort);
  if (!explicitPort || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host: parsed.hostname.replace(/^\[|\]$/g, ''), port };
}

function decodeNumericBanner(value = '') {
  const tokens = value.trim().split(/\s+/);
  if (tokens.length < 2 || !tokens.every((token) => /^\d{1,3}$/.test(token) && Number(token) <= 255)) return value;
  return tokens.map((token) => String.fromCharCode(Number(token))).join('');
}

async function geminiAnswer(prompt) {
  const response = await askGemini(prompt);
  if (response && !response.startsWith('[Gemini API')) return response.trim();
  return `Gemini did not provide a reasoning response. ${response || 'Check that GEMINI_API_KEY is configured on the server and retry.'}`;
}

export function resolveRsaChallenge(content = '', files = [], history = []) {
  const currentEvidence = [content, ...files.map((file) => file.content)].join('\n');
  const currentParameters = parseRsaParameters(currentEvidence);
  if (currentParameters) return { parameters: currentParameters, evidence: currentEvidence };
  if (!/\b(?:rsa|ciphertext|modulus|decrypt)\b/i.test(content)) return null;

  const historicalEvidence = history
    .filter((message) => message.role === 'user')
    .flatMap((message) => [
      message.content || '',
      ...(message.attachments || (message.attachment ? [message.attachment] : [])).map((file) => file.content || '')
    ])
    .filter(Boolean);
  for (let start = historicalEvidence.length - 1; start >= 0; start--) {
    const evidence = historicalEvidence.slice(start).join('\n').slice(-20000);
    const parameters = parseRsaParameters(evidence);
    if (parameters) return { parameters, evidence };
  }
  return null;
}

export async function answerChat(content, onMessage, history = [], attachments = []) {
  const emit = (message) => onMessage({ role: message.role, ...message });
  const normalized = (content || '').trim();
  const files = Array.isArray(attachments) ? attachments : (attachments ? [attachments] : []);
  const url = files.length ? null : extractUrl(normalized);
  const asksForTcpProbe = /\b(?:nc|netcat|tcp|banner)\b/i.test(normalized) || (/\bport\b/i.test(normalized) && /\b(?:probe|check|test|connect)\b/i.test(normalized));
  const urlTcpTarget = url && asksForTcpProbe ? parseTcpUrlTarget(url) : null;
  const serviceTarget = parseServiceTarget(normalized);
  const conversationHistory = formatHistory(history, normalized);
  const rsaChallenge = resolveRsaChallenge(normalized, files, history);

  if (!url) {
    const isChallenge = files.length > 0 || Boolean(rsaChallenge) || looksLikeChallengeEvidence(normalized) || Boolean(serviceTarget);
    if (!isChallenge) {
      const answer = await geminiAnswer(`You are a conversational assistant. Answer the user normally and helpfully based on their actual question. Do not rely on fixed keyword patterns. Treat this as a general chat request unless the user provides actual challenge evidence such as a URL, source snippet, binary path, or target and port.\n\nPrevious conversation:\n${conversationHistory}\n\nCurrent user message:\n${normalized}`);
      emit({ role: 'agent', kind: 'chat', content: answer });
      return;
    }
    if (isPythonChallengeRequest(normalized)) {
      const attachmentEvidence = files.map((file) => `\n\nAttached file (${file.name}):\n${file.content}`).join('');
      const pythonFiles = files.length ? files : [{ name: 'pasted-python-source', content: normalized }];
      const localScan = grepFiles(pythonFiles);
      emit({ role: 'agent', kind: 'tool_call', toolName: 'grep_files', content: `Locally scanning ${pythonFiles.length} Python source input(s) for embedded flags and secret-like strings.` });
      emit({ role: 'tool', kind: 'tool_result', toolName: 'grep_files', toolResult: localScan, content: JSON.stringify(localScan) });
      const answer = await geminiAnswer(`Solve the user's Python CTF challenge by carefully reasoning from the supplied source. Explain the relevant program behavior and give the requested result if it can be derived. Do not claim to have executed code; if a random value is chosen at runtime, distinguish that from values determinable from the source.\n\nPrevious conversation:\n${conversationHistory}\n\nUser request and source:\n${normalized}${attachmentEvidence}\n\nLocal flag and secret scan:\n${JSON.stringify(localScan)}`);
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
      const reply = await geminiAnswer(`You are reasoning on an authorized CTF service. Listen to the user's exact wording and the target details first. Do not stop at the first banner or the first failed hypothesis. If the output is noisy, encoded, or contains decoys, search for alternate evidence, hidden data, repeated clues, or a safe follow-up interaction requirement.\n\nPrevious conversation:\n${conversationHistory}\n\nCurrent user request / context:\n${content}\n\nTarget: ${serviceTarget.host}:${serviceTarget.port}\nObserved output:\n${banner || probe.error}\n\nFlag evidence from local inspection: ${flagEvidence || 'none found'}\n\nImportant: We are not exploiting anything. We are gathering evidence and looking for safe, authorized next steps. If this first read is not conclusive, explain what alternative evidence path should be tried next.`);
      emit({ role: 'agent', kind: 'chat', content: reply });
      return;
    }
    if (rsaChallenge) {
      const { parameters: rsaParameters, evidence: rsaEvidence } = rsaChallenge;
      emit({ role: 'agent', kind: 'hypothesis', content: 'I found RSA ciphertext, modulus, and exponent values. I will check for weak modulus factors and decrypt locally if they are recoverable.' });
      emit({ role: 'agent', kind: 'tool_call', toolName: 'rsa_decrypt', content: 'Factoring the supplied modulus with bounded local checks, then applying RSA decryption.' });
      let result = decryptRsaChallenge(rsaParameters);
      if (!result.ok) {
        emit({ role: 'agent', kind: 'tool_call', toolName: 'factor_database_lookup', content: 'Local factoring was inconclusive. Checking the public modulus against FactorDB; the ciphertext and file contents are not sent.' });
        const factors = await lookupRsaFactors(rsaParameters.modulus);
        if (factors) result = decryptRsaWithFactors(rsaParameters, factors, 'FactorDB');
      }
      emit({ role: 'tool', kind: 'tool_result', toolName: 'rsa_decrypt', toolResult: result, content: JSON.stringify(result) });
      const reply = await geminiAnswer(`Answer the user's RSA follow-up using the verified tool output below. Explain what the values show and point out any flag candidate. Do not redo large integer arithmetic or invent a plaintext; treat the tool result as authoritative. If decryption failed, explain what the error means and suggest a practical next step. Be concise.

    Earlier conversation:
    ${conversationHistory}

    Current request:
    ${content}

    RSA evidence:
    ${rsaEvidence}

    Verified RSA tool result:
    ${JSON.stringify(result)}`);
      emit({ role: 'agent', kind: 'chat', content: reply });
      return;
    }
    const source = files.length ? '' : content;
    const localScan = files.length ? grepFiles(files) : searchSource(source);
    if (localScan.matches?.length || files.length) {
      emit({ role: 'agent', kind: 'tool_call', toolName: files.length ? 'grep_files' : 'search_source', content: files.length ? `Searching ${files.length} attached file(s) for flag candidates, likely secrets, and source-risk patterns.` : 'Scanning the pasted snippet for input-to-sink patterns.' });
      emit({ role: 'tool', kind: 'tool_result', toolName: files.length ? 'grep_files' : 'search_source', toolResult: localScan, content: JSON.stringify(localScan) });
    }
    const attachmentEvidence = files.map((file) => `\n\nAttached file (${file.name}${file.truncated ? ', excerpt truncated to 20,000 characters' : ''}):\n${file.content}`).join('');
    const reply = await geminiAnswer(`Respond as a helpful assistant. Read every attached file's available content, report any flag candidates found, and for source files perform a security review grounded in the code. Distinguish confirmed issues from suspicious patterns.\n\nPrevious conversation:\n${conversationHistory}\n\nCurrent user message:\n${content}${attachmentEvidence}\n\nLocal grep-style scan result:\n${JSON.stringify(localScan)}`);
    emit({ role: 'agent', kind: 'chat', content: reply });
    return;
  }
  emit({ role: 'agent', kind: 'hypothesis', content: `I found a URL. I will retrieve its public challenge page, extract visible clues, and scan the response for leads.` });
  emit({ role: 'agent', kind: 'tool_call', toolName: 'fetch_authorized_url', content: 'Fetching the URL with an 8-second timeout and private-network protection.' });
  if (urlTcpTarget) emit({ role: 'agent', kind: 'tool_call', toolName: 'probe_tcp_service', content: `Reading the explicitly requested TCP banner from ${urlTcpTarget.host}:${urlTcpTarget.port} without sending data.` });
  const [fetched, tcpProbe] = await Promise.all([
    fetchAuthorizedUrl(url),
    urlTcpTarget ? probeTcpService(urlTcpTarget.host, urlTcpTarget.port) : Promise.resolve(null)
  ]);
  emit({ role: 'tool', kind: 'tool_result', toolName: 'fetch_authorized_url', toolResult: { ...fetched, text: undefined }, content: fetched.ok ? `Fetched ${fetched.status} ${fetched.contentType || ''} from ${fetched.url}` : fetched.error });
  if (tcpProbe) emit({ role: 'tool', kind: 'tool_result', toolName: 'probe_tcp_service', toolResult: tcpProbe, content: tcpProbe.ok ? tcpProbe.banner : tcpProbe.error });
  if (!fetched.ok) {
    if ([401, 403].includes(fetched.status)) {
      const blockedPageScan = grepFiles([{ name: fetched.url, content: fetched.text || '' }]);
      const blockedSurface = inspectWebSurface(fetched.text || '', fetched.url);
      emit({ role: 'agent', kind: 'tool_call', toolName: 'inspect_blocked_web_response', content: `Analyzing the ${fetched.status} response instead of treating it as an empty result.` });
      emit({ role: 'tool', kind: 'tool_result', toolName: 'inspect_blocked_web_response', toolResult: { status: fetched.status, headers: fetched.headers, pageScan: blockedPageScan, webSurface: blockedSurface }, content: JSON.stringify({ status: fetched.status, headers: fetched.headers, pageScan: blockedPageScan, webSurface: blockedSurface }) });
      const blockedReply = await geminiAnswer(`Analyze this authorized HTTPS challenge response that returned HTTP ${fetched.status}. Do not claim the target was bypassed or exploited. Explain whether the evidence suggests authentication, authorization, a WAF/rate limit, bot protection, a missing request requirement, or a potentially interesting information disclosure. Use the response headers, visible body, forms, scripts, links, and source scan. Recommend only safe next steps such as checking the public challenge instructions, using an authorized session, or comparing documented request requirements.\n\nPrevious conversation:\n${conversationHistory}\n\nCurrent user request:\n${content}\n\nURL: ${fetched.url}\nResponse headers:\n${JSON.stringify(fetched.headers)}\n\nWeb surface:\n${JSON.stringify(blockedSurface)}\n\nPage scan:\n${JSON.stringify(blockedPageScan)}\n\nResponse body excerpt:\n${fetched.text || '(empty response body)'}`);
      emit({ role: 'agent', kind: 'chat', content: blockedReply });
      return;
    }
    const reply = await geminiAnswer(`Explain this failed public challenge-page retrieval and give the user a useful next step. Do not claim to have inspected the page.\n\nUser request:\n${content}\n\nFetch result:\n${fetched.error}\n\nTCP probe result:\n${JSON.stringify(tcpProbe)}`);
    emit({ role: 'agent', kind: 'chat', content: reply });
    return;
  }
  const pageScan = grepFiles([{ name: fetched.url, content: fetched.text }]);
  emit({ role: 'agent', kind: 'tool_call', toolName: 'grep_files', content: 'Locally searching the fetched page for flag candidates and secret-like strings.' });
  emit({ role: 'tool', kind: 'tool_result', toolName: 'grep_files', toolResult: pageScan, content: JSON.stringify(pageScan) });
  const result = searchSource(fetched.text);
  const webSurface = inspectWebSurface(fetched.text, fetched.url);
  emit({ role: 'agent', kind: 'tool_call', toolName: 'inspect_web_surface', content: 'Inspecting forms, scripts, links, and query parameters for web-application leads.' });
  emit({ role: 'tool', kind: 'tool_result', toolName: 'inspect_web_surface', toolResult: webSurface, content: JSON.stringify(webSurface) });
  const reply = await geminiAnswer(`Treat this as a real investigation, not a static summary. Listen to the user’s challenge wording and follow the strongest evidence. If the page looks like a decoy or the first clue is weak, think of alternative routes: hidden encoded data, challenge type hints, command examples, or a second artifact to inspect.\n\nPrevious conversation:\n${conversationHistory}\n\nCurrent user request:\n${content}\n\nURL: ${fetched.url}\nWeb surface evidence: ${JSON.stringify(webSurface)}\nLocal flag/secret scan: ${JSON.stringify(pageScan)}\nLocal source-pattern scan: ${JSON.stringify(result)}\nTCP banner probe: ${JSON.stringify(tcpProbe)}\nPage excerpt:\n${fetched.text}\n\nDo not claim exploitation. Identify the likely challenge category, the strongest clue, and the next safe evidence to collect if the first idea does not pan out. For forms, parameters, scripts, or suspicious sinks, explain what could be tested only against an authorized target.`);
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