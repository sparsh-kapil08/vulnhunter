import { execFile } from 'node:child_process';
import net from 'node:net';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

function isBlockedHost(hostname) {
  const host = hostname.toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0' ||
    host === '169.254.169.254' || host.startsWith('10.') || host.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host);
}

export async function fetchAuthorizedUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return { ok: false, error: 'That is not a valid URL.' };
  }
  if (!['http:', 'https:'].includes(url.protocol) || isBlockedHost(url.hostname)) {
    return { ok: false, error: 'Only public HTTP(S) URLs are supported; local and private network targets are blocked.' };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(url, { signal: controller.signal, headers: { 'User-Agent': 'VulnHunter-authorized-research/1.0' } });
    const text = (await response.text()).slice(0, 120000);
    return { ok: response.ok, status: response.status, url: response.url, contentType: response.headers.get('content-type'), text };
  } catch (error) {
    return { ok: false, error: error.name === 'AbortError' ? 'The URL timed out after 8 seconds.' : error.message };
  } finally {
    clearTimeout(timer);
  }
}

export function searchSource(code = '') {
  const patterns = [
    { regex: /\b(eval|exec|execFile)\s*\(/g, reason: 'User-controlled data may reach command or code execution.' },
    { regex: /\b(query|query\s*=).*\+|\bSELECT.+\$\{/gi, reason: 'String-built SQL can allow injection.' },
    { regex: /innerHTML\s*=|\.html\s*\(/g, reason: 'Unsanitized HTML assignment can allow XSS.' },
    { regex: /child_process|spawn\s*\(/g, reason: 'Process execution should be isolated and input-validated.' }
  ];
  const matches = [];
  const lines = code.split(/\r?\n/);
  lines.forEach((line, index) => {
    patterns.forEach(({ regex, reason }) => {
      if (regex.test(line)) matches.push({ line: index + 1, code: line.trim(), reason });
      regex.lastIndex = 0;
    });
  });
  return { matches, scannedLines: lines.length, tool: 'search_source' };
}

export function inspectWebSurface(html = '', baseUrl = '') {
  const forms = [...html.matchAll(/<form\b[^>]*>/gi)].slice(0, 20).map((match) => match[0].slice(0, 500));
  const scripts = [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)].slice(0, 20).map((match) => match[1]);
  const links = [...html.matchAll(/(?:href|action)\s*=\s*["']([^"']+)["']/gi)].slice(0, 40).map((match) => {
    try { return new URL(match[1], baseUrl).toString(); } catch { return match[1]; }
  });
  const parameters = [...new Set(links.flatMap((link) => {
    try { return [...new URL(link).searchParams.keys()]; } catch { return []; }
  }))].slice(0, 40);
  return { tool: 'inspect_web_surface', forms, scripts, links, parameters };
}

export async function inspectBinary(binaryPath) {
  const result = { tool: 'inspect_binary', binaryPath, protections: [], strings: [] };
  try {
    const { stdout } = await execFileAsync('checksec', ['--file=' + binaryPath], { timeout: 5000 });
    result.protections = stdout.trim().split(/\r?\n/);
  } catch (error) {
    result.error = 'checksec unavailable or binary could not be inspected.';
  }
  return result;
}

export function craftPayload(vulnClass = 'unknown') {
  const payloads = {
    sqli: "' OR '1'='1",
    xss: '<script>alert(1)</script>',
    command_injection: '; echo VULNHUNTER_TEST',
    buffer_overflow: 'A'.repeat(64)
  };
  return { tool: 'craft_payload', vulnClass, payload: payloads[vulnClass] || 'No payload generated for this class.' };
}

export async function runInSandbox(target, input = '') {
  if (!target) return { tool: 'run_in_sandbox', error: 'A target is required.' };
  try {
    const { stdout, stderr } = await execFileAsync('docker', [
      'run', '--rm', '--network', 'none', '--read-only', '--memory', '256m', '--cpus', '0.5',
      target
    ], { input, timeout: 10000, maxBuffer: 100000 });
    return { tool: 'run_in_sandbox', stdout, stderr, network: 'none' };
  } catch (error) {
    return { tool: 'run_in_sandbox', error: error.message, network: 'none' };
  }
}

export function testPayload(payload, target) {
  return { tool: 'test_payload', target, payload, status: 'queued', note: 'Payload testing is restricted to the local sandbox.' };
}

export function probeTcpService(host, port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port: Number(port) });
    let banner = '';
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(5000, () => finish(banner ? { ok: true, host, port: Number(port), banner, timedOut: true } : { ok: false, host, port: Number(port), error: 'The service did not return a banner within 5 seconds.' }));
    socket.on('data', (chunk) => {
      banner += chunk.toString('utf8');
      if (banner.length >= 65536) finish({ ok: true, host, port: Number(port), banner: banner.slice(0, 65536), truncated: true });
    });
    socket.on('connect', () => {});
    socket.on('end', () => finish({ ok: true, host, port: Number(port), banner: banner || '(connected; service returned no output)' }));
    socket.on('error', (error) => finish({ ok: false, host, port: Number(port), error: error.message }));
  });
}