import test from 'node:test';
import assert from 'node:assert/strict';
import { buildGeminiSystemInstruction } from '../src/gemini.js';
import { looksLikeChallengeEvidence, buildGeneralChatReply } from '../src/orchestrator.js';

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
  const reply = buildGeneralChatReply('how to access a unrestricted psql');
  assert.match(reply, /how to access a unrestricted psql/i);
  assert.doesNotMatch(reply, /source-level sink patterns|investigation note/i);
});
