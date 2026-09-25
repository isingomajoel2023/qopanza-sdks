# Qopanza MCP server

Lets an AI coding agent — Claude Code, Cursor, Windsurf, Claude Desktop —
scan an app for exposed secrets and open databases, and then fix what it
finds.

The point is that the person using it never sees this. They type:

> check my app is secure before I launch

and the agent calls `scan_app_url`, gets structured findings back, calls
`get_fixes`, and applies the edits. No dashboard, no report to read, no
signup flow in the middle of their work.

## Why this exists rather than a CLI

The audience is someone who built an app on Lovable, Bolt, v0 or Replit.
They do not have a terminal habit, and a scan *report* is homework — a
list of things to go and do, in vocabulary they do not have. An agent
with these tools skips the report entirely and changes the code.

That also fixes the hardest part of the product: explaining what row-level
security is. The agent does not need it explained. It needs a policy and a
file to put it in, which is what `get_fixes` returns.

## Install

Nothing to clone or build. Your agent runs it with `npx`, which fetches
the published package the first time. Node 18 or newer.

**Claude Code:**

```bash
claude mcp add qopanza -e QOPANZA_API_KEY=qsk_... -- npx -y qopanza-mcp
```

**Cursor** (`~/.cursor/mcp.json`), **Windsurf** (`~/.codeium/windsurf/mcp_config.json`)
and **Claude Desktop** (`claude_desktop_config.json`) all take the same
block:

```json
{
  "mcpServers": {
    "qopanza": {
      "command": "npx",
      "args": ["-y", "qopanza-mcp"],
      "env": {
        "QOPANZA_API_KEY": "qsk_..."
      }
    }
  }
}
```

Then ask your agent something like *"scan https://myapp.com for exposed
secrets and fix what you find"*.

`QOPANZA_API_KEY` comes from **API Keys** in the dashboard; a free
account is enough for every tool except `get_fixes`. The key lives in
your agent's local config, never in your project's code. `QOPANZA_BASE_URL`
defaults to `https://api.qopanza.com/v1`; set it only for a self-hosted
deployment.

### From source

For working on the server itself:

```bash
cd mcp-server
npm install
npm run build
claude mcp add qopanza -- node "$(pwd)/dist/index.js"
```

## Tools

| Tool | Plan | What it does |
|---|---|---|
| `scan_app_url` | Free | Fetches a deployed site and reads the JavaScript it serves. Anything found is already public. |
| `scan_app_code` | Free | Scans one file's contents — what an agent calls while editing. |
| `get_fixes` | **Pro** | Turns findings into exact edits, config files and SQL policies. |
| `scan_crypto` | Free | The quantum-vulnerability scan, for code with its own cryptography. |

Every tool needs `QOPANZA_API_KEY`. Without one the server does not fail
silently: the agent is told the key is missing and where to get it. (The
no-account scan on qopanza.com/scan is a separate, rate-limited endpoint
this server does not use.)

## The thing an agent must not get wrong

`get_fixes` returns steps with an `automatable` flag. **Key rotation is
never automatable** — it happens in someone else's console, and this
server has no access to it.

An agent that applies the code edits and reports "fixed" while the leaked
key is still live has made things worse: the user now believes they are
safe. The tool descriptions say this explicitly, and every response
repeats the count of manual steps outstanding, because the model reads
the response far more carefully than it reads the schema.
