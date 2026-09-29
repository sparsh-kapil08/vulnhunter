import test from 'node:test';
import assert from 'node:assert/strict';
import { buildGeminiSystemInstruction } from '../src/gemini.js';
import { answerChat, looksLikeChallengeEvidence, parseTcpUrlTarget, resolveRsaChallenge } from '../src/orchestrator.js';
import { decryptRsaChallenge, decryptRsaWithFactors, grepFiles, parseRsaParameters, searchSource } from '../src/tools.js';
import { MAX_ATTACHMENT_CHARS, MAX_ATTACHMENTS, normalizeAttachment, normalizeAttachments } from '../src/uploads.js';

test('system instruction tells the model to adapt to user input and pivot on failed attempts', () => {
  const instruction = buildGeminiSystemInstruction();

  assert.match(instruction, /listen to the user/i);
  assert.match(instruction, /adapt/i);
  assert.match(instruction, /if one approach fails|alternative/i);
  assert.match(instruction, /fetchAuthorizedUrl|probeTcpService|searchSource|inspectBinary/i);
});

test('general conversation is not treated as challenge evidence', () => {
  assert.equal(looksLikeChallengeEvidence('hi'), false);
  assert.equal(looksLikeChallengeEvidence('helo'), false);
  assert.equal(looksLikeChallengeEvidence("What's a pipe?"), false);
  assert.equal(looksLikeChallengeEvidence('Connect to chatelaine.cylabacademy.net 27150'), true);
});

test('TCP target parsing accepts explicit URL ports but rejects private hosts', () => {
  assert.deepEqual(parseTcpUrlTarget('https://ctf.example:31337/challenge'), { host: 'ctf.example', port: 31337 });
  assert.deepEqual(parseTcpUrlTarget('https://ctf.example:443/challenge'), { host: 'ctf.example', port: 443 });
  assert.equal(parseTcpUrlTarget('http://127.0.0.1:8080/'), null);
  assert.equal(parseTcpUrlTarget('https://ctf.example/'), null);
});

test('file attachments are normalized, bounded, and accept extracted binary content', () => {
  const normalized = normalizeAttachment({ name: 'folder\\unsafe.js', content: 'const value = exec(input);' });
  assert.equal(normalized.name, 'unsafe.js');
  assert.equal(normalized.content, 'const value = exec(input);');
  assert.equal(normalized.truncated, false);
  assert.equal(searchSource(normalized.content).matches[0].line, 1);
  assert.equal(normalizeAttachment({ name: 'large.js', content: 'x'.repeat(MAX_ATTACHMENT_CHARS + 1) }).content.length, MAX_ATTACHMENT_CHARS);
  assert.equal(normalizeAttachment({ name: 'app.bin', content: 'flag{found_in_binary_strings}' }).name, 'app.bin');
  assert.throws(() => normalizeAttachment({ name: 'large.js', content: 'x'.repeat(256 * 1024 + 1) }), /256 KB or smaller/);
  assert.equal(MAX_ATTACHMENTS, 3);
  assert.equal(normalizeAttachments([{ name: 'one.bin', content: 'A' }, { name: 'two.pdf', content: 'B' }, { name: 'three.zip', content: 'C' }]).length, 3);
  assert.throws(() => normalizeAttachments(Array.from({ length: 4 }, (_, index) => ({ name: `${index}.txt`, content: 'x' }))), /no more than 3 files/);
});

test('file grep scan reports flag candidates, keyword lines, and source-risk patterns', () => {
  const result = grepFiles([{ name: 'challenge.dat', content: 'picoCTF{read_from_file}\npassword = "hunter2"\nexec(input);' }]);
  assert.equal(result.tool, 'grep_files');
  assert.equal(result.files[0].flagCandidates[0].value, 'picoCTF{read_from_file}');
  assert.equal(result.files[0].keywordMatches[0].line, 2);
  assert.equal(result.files[0].sourceMatches[0].line, 3);
});

test('RSA challenge values are parsed and weak moduli are decrypted locally', () => {
  const values = parseRsaParameters(`Decrypt my super sick RSA:\nc: 2790\nn: 3233\ne: 17`);
  assert.deepEqual(values, { ciphertext: 2790n, modulus: 3233n, exponent: 17n });
  const result = decryptRsaChallenge(values);
  assert.equal(result.ok, true);
  assert.equal(result.plaintextHex, '41');
  const suppliedFactors = decryptRsaWithFactors(values, [{ value: 53n, power: 1 }, { value: 61n, power: 1 }], 'test');
  assert.equal(suppliedFactors.plaintextUtf8, 'A');
  assert.equal(looksLikeChallengeEvidence('In RSA, c: 2790 n: 3233 e: 17'), true);
  assert.equal(parseRsaParameters('n: 3233\ne: 17'), null);
});

test('RSA challenge decrypts with validated factors for the supplied modulus', () => {
  const values = parseRsaParameters('c: 717608817902276639011922897702552744324264244069272484013719744328086856277690292\nn: 1368992139315019955067447961537607041364451719382349005056752379702694554965203011\ne: 65537');
  const factors = [
    { value: 2074606527507983503944226222695401999839n, power: 1 },
    { value: 659880377875535146491994798968813949893149n, power: 1 }
  ];
  const result = decryptRsaWithFactors(values, factors, 'FactorDB');
  assert.equal(result.ok, true);
  assert.equal(result.factorSource, 'FactorDB');
  assert.ok(result.plaintextHex.length > 0);
  assert.equal(decryptRsaWithFactors(values, [{ value: 53n, power: 1 }]).ok, false);
});

test('RSA follow-ups reuse the most recent user attachment containing the challenge values', () => {
  const result = resolveRsaChallenge('re analyze the rsa', [], [
    { role: 'user', content: 'Please analyze the attached file "values".', attachments: [{ name: 'values', content: 'c: 2790\nn: 3233\ne: 17' }] },
    { role: 'agent', content: 'Earlier generic response.' }
  ]);
  assert.deepEqual(result.parameters, { ciphertext: 2790n, modulus: 3233n, exponent: 17n });
  assert.equal(resolveRsaChallenge('re analyze the rsa', [], [{ role: 'user', content: 'nothing here' }]), null);
});

test('RSA follow-up response uses Gemini with verified decryption evidence', async () => {
  const originalFetch = globalThis.fetch;
  const originalApiKey = process.env.GEMINI_API_KEY;
  let geminiPrompt = '';
  const emitted = [];
  process.env.GEMINI_API_KEY = 'test-key';
  globalThis.fetch = async (_url, options) => {
    geminiPrompt = JSON.parse(options.body).contents[0].parts[0].text;
    return { ok: true, json: async () => ({ candidates: [{ content: { parts: [{ text: 'Gemini analyzed the verified RSA result.' }] } }] }) };
  };

  try {
    await answerChat('re analyze the rsa', (message) => emitted.push(message), [
      { role: 'user', content: 'Please analyze the attached file "values".', attachments: [{ name: 'values', content: 'c: 2790\nn: 3233\ne: 17' }] }
    ]);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalApiKey === undefined) delete process.env.GEMINI_API_KEY;
    else process.env.GEMINI_API_KEY = originalApiKey;
  }

  assert.match(geminiPrompt, /Verified RSA tool result/);
  assert.match(geminiPrompt, /plaintextUtf8.*A/);
  assert.equal(emitted.at(-1).content, 'Gemini analyzed the verified RSA result.');
});

test('Python flag-script requests use Gemini instead of the canned fallback', async () => {
  const originalFetch = globalThis.fetch;
  const originalApiKey = process.env.GEMINI_API_KEY;
  let geminiPrompt = '';
  const emitted = [];
  process.env.GEMINI_API_KEY = 'test-key';
  globalThis.fetch = async (url, options) => {
    assert.match(url, /generativelanguage\.googleapis\.com/);
    geminiPrompt = JSON.parse(options.body).contents[0].parts[0].text;
    return { ok: true, json: async () => ({ candidates: [{ content: { parts: [{ text: 'Gemini solved the Python challenge.' }] } }] }) };
  };

  try {
    await answerChat('Run the Python script and convert the given number from decimal to binary to get the flag.\n\nprint("flag challenge")', (message) => emitted.push(message));
  } finally {
    globalThis.fetch = originalFetch;
    if (originalApiKey === undefined) delete process.env.GEMINI_API_KEY;
    else process.env.GEMINI_API_KEY = originalApiKey;
  }

  assert.match(geminiPrompt, /Solve the user's Python CTF challenge/);
  assert.match(geminiPrompt, /print\("flag challenge"\)/);
  assert.equal(emitted.at(-1).content, 'Gemini solved the Python challenge.');
  assert.ok(emitted.some((message) => message.toolName === 'grep_files' && message.kind === 'tool_result'));
});

test('URL investigations grep fetched page content locally before Gemini reasoning', async () => {
  const originalFetch = globalThis.fetch;
  const originalApiKey = process.env.GEMINI_API_KEY;
  const emitted = [];
  let geminiPrompt = '';
  process.env.GEMINI_API_KEY = 'test-key';
  globalThis.fetch = async (url, options) => {
    if (String(url).includes('generativelanguage.googleapis.com')) {
      geminiPrompt = JSON.parse(options.body).contents[0].parts[0].text;
      return { ok: true, json: async () => ({ candidates: [{ content: { parts: [{ text: 'Gemini reviewed the page scan.' }] } }] }) };
    }
    return {
      ok: true,
      status: 200,
      url: 'https://ctf.example/',
      headers: { get: () => 'text/html' },
      text: async () => '<html><body>picoCTF{visible_page_flag}</body></html>'
    };
  };

  try {
    await answerChat('Find the flag on https://ctf.example/', (message) => emitted.push(message));
  } finally {
    globalThis.fetch = originalFetch;
    if (originalApiKey === undefined) delete process.env.GEMINI_API_KEY;
    else process.env.GEMINI_API_KEY = originalApiKey;
  }

  const grepResult = emitted.find((message) => message.toolName === 'grep_files' && message.kind === 'tool_result');
  assert.equal(grepResult.toolResult.files[0].flagCandidates[0].value, 'picoCTF{visible_page_flag}');
  assert.match(geminiPrompt, /visible_page_flag/);
  assert.equal(emitted.at(-1).content, 'Gemini reviewed the page scan.');
});

test('Python challenge does not return the canned reply when Gemini has no API key', async () => {
  const originalApiKey = process.env.GEMINI_API_KEY;
  const emitted = [];
  delete process.env.GEMINI_API_KEY;

  try {
    await answerChat('Run the Python script and convert decimal to binary to get the flag.\nprint("flag")', (message) => emitted.push(message));
  } finally {
    if (originalApiKey === undefined) delete process.env.GEMINI_API_KEY;
    else process.env.GEMINI_API_KEY = originalApiKey;
  }

  assert.match(emitted.at(-1).content, /Gemini did not provide a reasoning response/i);
  assert.doesNotMatch(emitted.at(-1).content, /Please provide any relevant context/i);
});
