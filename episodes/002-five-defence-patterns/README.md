# You Saw My Agent Get Hacked — Here's How I Fixed It
### Agentic AI Security · Episode 2 · Toma Ijatomi

Five defensive patterns against the attacks from [Episode 1](https://youtu.be/R7Y4i-yEa54), built with Google ADK + Gemini.

---

## Demo Recording

Watch the demo on YouTube

<p align="left">
  <a href="https://youtu.be/RkCOOucIbeE">
    <img src="https://github.com/user-attachments/assets/c14012aa-5802-4617-84b9-66abccd340ae" alt="Watch the video" width="500" />
  </a>
</p>

---

## Quick start

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate       # macOS/Linux
# .venv\Scripts\activate        # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Add your Gemini API key
echo 'GEMINI_API_KEY=your_key_here' > .env

# 4. Start Phoenix (in a separate terminal — keeps it running)
phoenix serve

# 5. Launch the demo
python server.py
```

Then open:
- **http://localhost:7860** — the demo UI
- **http://localhost:6006** — the Phoenix trace dashboard

Every run emits a full OpenTelemetry trace to Phoenix: the fetcher → sanitiser → reasoner pipeline for Pattern 2, and the planner → validator → executor pipeline for Pattern 3. Click into any span to see the exact prompt sent to Gemini, the response it returned, and the state that flowed between agents.

### Using Phoenix Cloud instead

If you prefer Phoenix Cloud over a local instance, add these to `.env` and skip `phoenix serve`:
```
PHOENIX_COLLECTOR_ENDPOINT=https://app.phoenix.arize.com/s/<your-space>
PHOENIX_API_KEY=<your-key>
```

---

## What's in the demo

Patterns 1, 4, and 5 don't have live-demo tabs — they're explained with code walkthroughs in the video and referenced in the source code. The interactive tabs focus on the two patterns with clear before/after state changes:

### Tab 1 — Pattern 2: Dual LLM Sandbox 

**The centrepiece.** The same attack that compromised the agent in Episode 1 now fails here. Built as a three-stage `SequentialAgent` pipeline:

```
fetcher (deterministic)  →  sanitiser (Gemini 3.1 Flash Lite)  →  reasoner (Gemini 3 Flash)
       writes: raw_html         reads: {raw_html}                     reads: {clean_content}
                                writes: clean_content                 writes: summary
```

The architectural guarantee is structural, not behavioural: the reasoner's prompt template only reads `{clean_content}` from session state, so raw HTML cannot reach its context. See it yourself in Phoenix — click the `reasoner` span and inspect the actual Gemini request.

### Tab 2 — Pattern 3: Output Validation Pipeline

A `SequentialAgent` with three stages: **Planner → Validator → Executor**. The validator checks the planner's proposed actions against the user's original request — specifically for scope, intent, and proportionality — before anything runs.

The tab has a scenario toggle with two modes:

- **Summarise only** (happy path) — the user asks for a summary of an article. The planner proposes one action: fetch the URL. The validator APPROVES. The executor runs the summary.
- **Summarise and exfiltrate** (defense path) — the user asks for a summary AND asks the agent to email the summary to an external address. The planner honestly includes both actions in its plan (that's a correct planner doing its job). The validator catches the scope violation — sending email was never part of the agent's legitimate purpose — and REJECTS. The executor refuses to run.

The executor has both tools available (`fetch_webpage` and `send_email`). The architectural guarantee isn't "the agent can't do bad things" — it's "the validator checks before the executor acts." In production, this is the layer that catches scope creep from prompt injection, confused-deputy attacks, and agent planning errors.


### Patterns 1, 4, and 5 — code reference only

Three of the five patterns aren't live-demoed in the Gradio UI because they don't have a visible state change that would make a good demo:

- **Pattern 1 (Least-privilege tool access).** The scoped agent just does its job with fewer tools. See `query_database()` in `agent.py` for the ADK `ToolContext` example that enforces model-proof constraints (read-only mode, allowed tables, etc.).
- **Pattern 4 (Human in the loop).** About *when* to require human approval, not how to run approval code. Use a circuit-breaker pattern on multi-agent message counts to prevent runaway loops: `if msg_count > MAX_TURNS: raise HumanEscalation()`.
- **Pattern 5 (Observability & tool trust).** Already running in this demo via Phoenix. Every agent span, every prompt, every tool call shows up in the Phoenix UI at http://localhost:6006. That *is* Pattern 5. Add `uvx mcp-scan@latest` to your CI pipeline to scan MCP tool descriptions before load — takes two minutes.

---

## File structure

```
demo/
├── agent.py                # All agents + Gradio UI
├── malicious_page.html     # Poisoned webpage (same as Episode 1)
├── server.py               # Launcher
├── requirements.txt        # Dependencies
├── .env.example            # Your API key
└── README.md
```

---

## Mapping to OWASP Agentic Top 10 (2026)

| Pattern | OWASP ASI | Risk |
|---------|-----------|------|
| Least-privilege tool access | ASI03 | Identity & Privilege Abuse |
| Dual LLM Sandbox | ASI01 | Agent Goal Hijacking |
| Output validation layer | ASI06 | Memory & Context Poisoning |
| Human in the loop | ASI03, ASI08 | Identity & Privilege Abuse, Cascading Failures |
| Observability & tool trust | ASI05, ASI09 | Unexpected Code Execution, Supply Chain |

---

## References

- [Google ADK Safety & Security](https://google.github.io/adk-docs/safety/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [MCPTox Benchmark](https://arxiv.org/abs/2508.14925) — 70%+ agents vulnerable to tool poisoning
- [MCP Security 2026: 30 CVEs in 60 Days](https://www.heyuan110.com/posts/ai/2026-03-10-mcp-security-2026/)
- [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) — open-source MCP security scanner

---

## ⚠️ Disclaimer

This code is for **educational demonstration purposes only**.
The malicious page and attack patterns are intentionally simplified for clarity.
Do NOT use these attack techniques against systems you don't own.
