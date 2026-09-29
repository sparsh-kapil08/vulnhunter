import { execFile } from 'node:child_process';
import net from 'node:net';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export function isBlockedHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
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
    return {
      ok: response.ok,
      status: response.status,
      url: response.url,
      contentType: response.headers.get('content-type'),
      headers: Object.fromEntries(['server', 'location', 'www-authenticate', 'content-security-policy', 'x-frame-options'].map((name) => [name, response.headers.get(name)]).filter(([, value]) => value)),
      text
    };
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

export function grepFiles(files = []) {
  const scannedFiles = files.map((file) => {
    const lines = file.content.split(/\r?\n/);
    const flagCandidates = [];
    const keywordMatches = [];
    lines.forEach((line, index) => {
      for (const match of line.matchAll(/[A-Za-z0-9_-]{2,}\{[^}\r\n]{1,200}\}/g)) {
        flagCandidates.push({ line: index + 1, value: match[0] });
      }
      if (/\b(flag|secret|password|token)\b/i.test(line)) {
        keywordMatches.push({ line: index + 1, text: line.trim().slice(0, 500) });
      }
    });
    const sourceScan = searchSource(file.content);
    return {
      name: file.name,
      scannedLines: lines.length,
      flagCandidates: flagCandidates.slice(0, 50),
      keywordMatches: keywordMatches.slice(0, 50),
      sourceMatches: sourceScan.matches.slice(0, 50)
    };
  });
  return { tool: 'grep_files', files: scannedFiles };
}

export function parseRsaParameters(value = '') {
  const readInteger = (names) => {
    const match = value.match(new RegExp(`\\b(?:${names})\\s*[:=]\\s*(\\d+)`, 'i'));
    return match ? BigInt(match[1]) : null;
  };
  const ciphertext = readInteger('c|ciphertext');
  const modulus = readInteger('n|modulus');
  const exponent = readInteger('e|exponent');
  if (ciphertext === null || modulus === null || exponent === null || modulus <= 1n || exponent <= 0n || ciphertext < 0n || ciphertext >= modulus) return null;
  return { ciphertext, modulus, exponent };
}

function greatestCommonDivisor(left, right) {
  while (right) [left, right] = [right, left % right];
  return left;
}

function integerSquareRoot(value) {
  if (value < 2n) return value;
  let current = value;
  let next = (current + 1n) >> 1n;
  while (next < current) {
    current = next;
    next = (current + value / current) >> 1n;
  }
  return current;
}

function modularPower(base, exponent, modulus) {
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = result * base % modulus;
    base = base * base % modulus;
    exponent >>= 1n;
  }
  return result;
}

function modularInverse(value, modulus) {
  let [oldR, remainder] = [value, modulus];
  let [oldCoefficient, coefficient] = [1n, 0n];
  while (remainder) {
    const quotient = oldR / remainder;
    [oldR, remainder] = [remainder, oldR - quotient * remainder];
    [oldCoefficient, coefficient] = [coefficient, oldCoefficient - quotient * coefficient];
  }
  return oldR === 1n ? (oldCoefficient % modulus + modulus) % modulus : null;
}

export function decryptRsaWithFactors({ ciphertext, modulus, exponent }, factors, factorSource = 'local') {
  if (!Array.isArray(factors) || factors.some((factor) => factor.value <= 1n || !Number.isSafeInteger(factor.power) || factor.power < 1)) {
    return { tool: 'rsa_decrypt', ok: false, error: 'The supplied factor data is invalid.' };
  }
  const factorProduct = factors.reduce((product, factor) => product * factor.value ** BigInt(factor.power), 1n);
  if (factorProduct !== modulus) {
    return { tool: 'rsa_decrypt', ok: false, error: 'The supplied factors do not multiply back to the RSA modulus.' };
  }
  const totient = factors.reduce((product, factor) => product * (factor.value - 1n) * factor.value ** BigInt(factor.power - 1), 1n);
  const privateExponent = modularInverse(exponent, totient);
  if (!privateExponent) {
    return { tool: 'rsa_decrypt', ok: false, error: 'The public exponent has no inverse modulo phi(n), so standard RSA decryption is not available.' };
  }
  const plaintext = modularPower(ciphertext, privateExponent, modulus);
  const hex = plaintext.toString(16);
  const plaintextHex = hex.padStart(hex.length + hex.length % 2, '0');
  const plaintextUtf8 = Buffer.from(plaintextHex, 'hex').toString('utf8');
  return {
    tool: 'rsa_decrypt',
    ok: true,
    factors: factors.map((factor) => factor.value.toString()),
    factorSource,
    plaintextHex,
    plaintextUtf8,
    flagCandidates: plaintextUtf8.match(/[A-Za-z0-9_-]{2,}\{[^}\r\n]{1,200}\}/g) || [],
    modulusBits: modulus.toString(2).length
  };
}

function findRsaFactor(modulus) {
  for (let divisor = 2n; divisor <= 1000n; divisor++) {
    if (modulus % divisor === 0n) return divisor;
  }

  let candidate = integerSquareRoot(modulus);
  if (candidate * candidate < modulus) candidate++;
  for (let iteration = 0; iteration < 10000; iteration++, candidate++) {
    const difference = candidate * candidate - modulus;
    const other = integerSquareRoot(difference);
    if (other * other === difference && candidate > other) return candidate - other;
  }

  for (let constant = 1n; constant <= 12n; constant++) {
    let slow = 2n;
    let fast = 2n;
    let factor = 1n;
    for (let iteration = 0; iteration < 100000 && factor === 1n; iteration++) {
      slow = (slow * slow + constant) % modulus;
      fast = (fast * fast + constant) % modulus;
      fast = (fast * fast + constant) % modulus;
      factor = greatestCommonDivisor(slow > fast ? slow - fast : fast - slow, modulus);
    }
    if (factor > 1n && factor < modulus) return factor;
  }
  return null;
}

export function decryptRsaChallenge({ ciphertext, modulus, exponent }) {
  const factor = findRsaFactor(modulus);
  if (!factor) {
    return { tool: 'rsa_decrypt', ok: false, modulusBits: modulus.toString(2).length, error: 'Could not factor the modulus within the bounded local search. The modulus may need an external factorization source or a different RSA attack.' };
  }
  return decryptRsaWithFactors({ ciphertext, modulus, exponent }, [
    { value: factor, power: 1 },
    { value: modulus / factor, power: 1 }
  ]);
}

export async function lookupRsaFactors(modulus) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(`https://factordb.com/api?query=${modulus}`, { signal: controller.signal });
    if (!response.ok) return null;
    const data = await response.json();
    if (data.status !== 'FF' || !Array.isArray(data.factors)) return null;
    const factors = data.factors.map(([value, power]) => ({ value: BigInt(value), power: Number(power) }));
    if (factors.reduce((product, factor) => product * factor.value ** BigInt(factor.power), 1n) !== modulus) return null;
    return factors;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
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