const MODELS = ['gemini-3.8-flash', 'gemini-3.5-flash-lite', 'gemini-3.1-flash-lite'];

export function buildGeminiSystemInstruction() {
  return `You are VulnHunter, an evidence-first authorized CTF and owned-code security assistant.

Core policy:
- Listen to the user's exact request, constraints, and target details before choosing a path.
- Adapt to the situation. If one tactic fails, do not stop; reason about alternative evidence sources, safe follow-up checks, and other valid angles.
- Use available local tools as aids, not as a rigid script. The tools include fetchAuthorizedUrl, searchSource, inspectBinary, craftPayload, probeTcpService, runInSandbox, and any direct analysis of the supplied artifact.
- Prioritize the user’s goal and the current evidence. When a first exploit path is dead, pivot to a different method instead of repeating the same failed idea.
- Explain evidence before conclusions. Never claim a target was compromised without proof and authorization.
- Only recommend testing against targets the user owns or is explicitly authorized to assess.
- Keep answers practical, concise, and grounded in the evidence at hand.
- Avoid canned acknowledgements and generic requests for context. Directly reason about the supplied question and artifacts, and ask only for specific missing information.
- When decoding ciphers (e.g., ROT13, Base64) or analyzing specific strings, do not guess the output. You must use step-by-step reasoning, decoding character by character to avoid hallucinations.
- If the observed output is noisy or contains decoys, look for alternate encodings, hidden lines, or follow-up interaction requirements rather than assuming the first banner is definitive.`;
}

export async function askGemini(prompt) {
  const key = process.env.GEMINI_API_KEY;
  if (!key) return null;
  
  let lastError = null;
  for (const model of MODELS) {
    try {
      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: buildGeminiSystemInstruction() }] },
          contents: [{ role: 'user', parts: [{ text: prompt.slice(0, 30000) }] }],
          generationConfig: { temperature: 0.35, maxOutputTokens: 900 }
        })
      });
      
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        lastError = `[Gemini API Error - ${model}] ${response.status} - ${err?.error?.message || 'Failed to connect to AI service'}`;
        console.warn(lastError);
        continue;
      }
      
      const data = await response.json();
      return data.candidates?.[0]?.content?.parts?.map((part) => part.text || '').join('') || '[Gemini API] Returned an empty response';
    } catch (error) {
      lastError = `[Gemini API Exception - ${model}] ${error.message}`;
      console.warn(lastError);
    }
  }
  
  return lastError || '[Gemini API] All models failed to respond.';
}