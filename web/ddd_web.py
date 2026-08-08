#!/usr/bin/env python3
"""A web interface for ddd, in the shape of qira/IDA/Binary Ninja.

    ./web/ddd_web.py --file=/bin/ls
    ./web/ddd_web.py --file=fw.bin --sla=ARM7_le --base=0x8000000

Spawns `sleigh_poc --server` and proxies to it. The C++ side holds the loaded
image and every analysis, which is the whole reason for a persistent process:
re-parsing a 10MB ELF per request would make the interface unusable, which is
exactly what the first attempt at interactivity got wrong.

The protocol is deliberately lopsided -- command lines out, one line of JSON
back -- so there is no JSON reader in the C++ binary and no serialisation
library on either side.
"""

import argparse
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
import urllib.parse


class Analyser:
    """The `sleigh_poc --server` process, serialised across requests.

    One process, one lock: the server answers one command at a time, and a web
    page will happily fire five requests at once.
    """

    def __init__(self, binary, path, specs, project, extra=()):
        command = [binary, "--file=" + path, "--specs=" + specs, "--server"]
        if project:
            command.append("--project=" + project)
        command += [flag for flag in extra if flag]

        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, bufsize=1)
        self.lock = threading.Lock()

    def ask(self, command):
        with self.lock:
            if self.process.poll() is not None:
                return {"error": "analyser exited"}

            self.process.stdin.write(command + "\n")
            self.process.stdin.flush()

            line = self.process.stdout.readline()
            if not line:
                return {"error": "analyser closed the connection"}

            try:
                return json.loads(line)
            except json.JSONDecodeError as problem:
                return {"error": f"bad response: {problem}"}

    def close(self):
        with self.lock:
            if self.process.poll() is None:
                try:
                    self.process.stdin.write("quit\n")
                    self.process.stdin.flush()
                except BrokenPipeError:
                    pass
                self.process.wait(timeout=5)


PAGE = r"""
<!doctype html>
<meta charset="utf-8">
<title>ddd</title>
<style>
  :root {
    --bg: #14161a; --panel: #1b1e24; --line: #2a2f38; --text: #d7dbe0;
    --dim: #7d8794; --key: #c58af9; --var: #79c0ff; --const: #ffa657;
    --op: #a5b0bd; --comment: #6f8f5e; --hi: #4d3b00; --sel: #23303f;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 13px/1.55 ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    display: grid; grid-template-columns: 260px 1fr 300px; height: 100vh;
  }
  .panel { overflow: auto; border-right: 1px solid var(--line); }
  .panel:last-child { border-right: 0; border-left: 1px solid var(--line); }
  h2 {
    font-size: 11px; text-transform: uppercase; letter-spacing: .08em;
    color: var(--dim); margin: 0; padding: 10px 12px 6px;
    position: sticky; top: 0; background: var(--panel); z-index: 1;
  }
  .panel { background: var(--panel); }
  #listing { background: var(--bg); }
  input {
    width: calc(100% - 24px); margin: 0 12px 8px; padding: 5px 7px;
    background: var(--bg); color: var(--text);
    border: 1px solid var(--line); border-radius: 4px; font: inherit;
  }
  .fn { padding: 3px 12px; cursor: pointer; white-space: nowrap;
        overflow: hidden; text-overflow: ellipsis; }
  .fn:hover { background: var(--sel); }
  .fn.on { background: var(--sel); color: #fff; }
  .fn .addr { color: var(--dim); margin-right: 8px; }

  .block { margin: 0 0 14px; }
  .blockhead {
    color: var(--dim); padding: 2px 12px; border-top: 1px solid var(--line);
  }
  .line { padding: 0 12px; white-space: pre-wrap; }
  .line:hover { background: #1a1d23; }
  .line .addr { color: var(--dim); margin-right: 12px; }
  .tok { padding: 0 1px; border-radius: 2px; }
  .k-var { color: var(--var); cursor: pointer; }
  .k-const { color: var(--const); }
  .k-op, .k-punct { color: var(--op); }
  .k-keyword { color: var(--key); }
  .k-cast { color: var(--dim); }
  .k-block { color: var(--key); cursor: pointer; text-decoration: underline; }
  .tok.hi { background: var(--hi); color: #fff; }
  .cmt { color: var(--comment); }
  .bcmt { color: var(--comment); padding: 0 12px; }

  .ref { padding: 3px 12px; cursor: pointer; }
  .ref:hover { background: var(--sel); }
  .ref .kind { color: var(--dim); margin-left: 6px; }
  .hint { color: var(--dim); padding: 6px 12px; font-size: 11px; }
  .line.cur { background: var(--sel); }
  .xref { color: var(--comment); padding: 0 12px; font-size: 12px; }
  .item { padding: 2px 12px; cursor: pointer; white-space: pre; }
  .item:hover { background: var(--sel); }
  .item .addr { color: var(--dim); }
  .item .val { color: var(--const); }
  .item .str { color: var(--comment); }
  .item .tgt { color: var(--var); }
  .item .n { color: var(--dim); }
  #modal { display: none; position: fixed; inset: 0; background: #0008;
           align-items: center; justify-content: center; }
  #modal.on { display: flex; }
  #modalbox { background: var(--panel); border: 1px solid var(--line);
              border-radius: 6px; padding: 14px; min-width: 420px;
              max-height: 70vh; overflow: auto; }
  #modaltitle { color: var(--dim); margin-bottom: 8px; }
  #modalinput { width: 100%; margin: 0; }
</style>

<div class="panel">
  <h2>functions</h2>
  <input id="filter" placeholder="filter">
  <div id="functions"></div>
</div>

<div class="panel" id="listing">
  <h2 id="title">ddd</h2>
  <div class="hint" id="hint">pick a function, or press g. click a variable to
    highlight it everywhere; double-click to rename; shift-click for a type;
    click an address to look at the bytes there.</div>
  <div id="code"></div>
</div>

<div class="panel">
  <h2 id="datahead">data</h2>
  <div class="hint">g goto &middot; x xrefs &middot; n rename &middot; y type &middot;
    ; comment &middot; Esc back</div>
  <div id="side"></div>
</div>

<div id="modal"><div id="modalbox">
  <div id="modaltitle"></div>
  <div id="modalbody"></div>
  <input id="modalinput" style="display:none">
</div></div>

<script>
const $ = (id) => document.getElementById(id);
let current = null;   // the function on screen
let selected = null;  // the token id last clicked -- what n/y act on
let cursor = null;    // the line the keyboard acts on
let dataAt = null;    // where the data pane is looking
const past = [];      // where we came from, for Esc

const ask = async (cmd) =>
  (await fetch("/api?" + new URLSearchParams({cmd}))).json();

const hex = (n) => "0x" + n.toString(16);

// ---------------------------------------------------------------- the modal
//
// Text entry and choosers both live here rather than in prompt(): a chooser
// has to be a list you can click, and prompt() steals the keyboard in a way
// that makes a keyboard-driven interface feel broken.

function openModal(title) {
  $("modaltitle").textContent = title;
  $("modalbody").innerHTML = "";
  $("modalinput").style.display = "none";
  $("modal").classList.add("on");
}

function closeModal() { $("modal").classList.remove("on"); }

function askText(title, initial) {
  return new Promise((done) => {
    openModal(title);
    const box = $("modalinput");
    box.style.display = "";
    box.value = initial || "";
    box.onkeydown = (e) => {
      e.stopPropagation();
      if (e.key === "Enter") { closeModal(); done(box.value.trim()); }
      if (e.key === "Escape") { closeModal(); done(null); }
    };
    box.focus();
    box.select();
  });
}

function askChoice(title, rows) {
  openModal(title);
  if (!rows.length) {
    $("modalbody").innerHTML = '<div class="hint">nothing</div>';
    return;
  }
  for (const row of rows) {
    const el = document.createElement("div");
    el.className = "ref";
    el.innerHTML = row.text;
    el.onclick = () => { closeModal(); row.go(); };
    $("modalbody").appendChild(el);
  }
}

// ----------------------------------------------------------------- browsing

function here() {
  if (current) return "function " + current.addr;
  if (dataAt !== null) return "data " + dataAt;
  return null;
}

function back() {
  closeModal();
  const to = past.pop();
  if (to) go(to, false);
}

// One address, one destination: code opens as a listing, everything else
// opens in the data pane. Which it is, is the analyser's call, not the UI's.
async function go(where, remember = true) {
  const from = here();
  const listing = await ask("function " + where);
  if (!listing.error) {
    if (remember && from) past.push(from);
    render(listing);
    return true;
  }

  const data = await ask("data " + where + " 64");
  if (!data.error) {
    if (remember && from) past.push(from);
    showData(data);
    return true;
  }
  return false;
}

async function loadFunctions(pattern) {
  const data = await ask("functions " + (pattern || ""));
  const list = $("functions");
  list.innerHTML = "";
  for (const fn of (data.functions || [])) {
    const row = document.createElement("div");
    row.className = "fn" + (current && current.addr === fn.addr ? " on" : "");
    row.innerHTML = `<span class="addr">${hex(fn.addr)}</span>${fn.name}`;
    row.onclick = () => go(fn.symbol);
    list.appendChild(row);
  }
}

// Highlighting is by token identity, not by matching text: `RAX` appears
// inside `RAX_2`, and a word-boundary regex would get that wrong.
function highlight(id) {
  selected = id;
  document.querySelectorAll(".tok").forEach((t) =>
    t.classList.toggle("hi", !!id && t.dataset.id === id));
}

function setCursor(row) {
  if (cursor) cursor.classList.remove("cur");
  cursor = row;
  if (!row) return;
  row.classList.add("cur");
  row.scrollIntoView({block: "nearest"});
}

function moveCursor(step) {
  const rows = [...document.querySelectorAll("#code .line")];
  if (!rows.length) return;
  const at = cursor ? rows.indexOf(cursor) : -1;
  setCursor(rows[Math.min(rows.length - 1, Math.max(0, at + step))]);
}

const cursorAddr = () =>
  cursor ? Number(cursor.dataset.addr) : (current ? current.addr : dataAt);

function renderTokens(line) {
  const span = document.createElement("span");
  for (const tok of line.tokens) {
    const el = document.createElement("span");
    el.className = "tok k-" + tok.k;
    el.textContent = tok.s;
    if (tok.id) {
      el.dataset.id = tok.id;
      el.onclick = (e) => { e.stopPropagation(); highlight(tok.id); };
      el.ondblclick = (e) => { e.stopPropagation(); rename(tok.id); };
      el.onmousedown = (e) => {
        if (e.shiftKey) { e.preventDefault(); setType(tok.id); }
      };
    }
    // A constant that lands inside the image is worth following: on ARM the
    // interesting ones are the literal pool words a nearby load reads.
    if (tok.k === "const") {
      const value = Number(tok.s);
      if (Number.isFinite(value) && value > 0xff)
        el.onclick = (e) => { e.stopPropagation(); go(String(value)); };
    }
    if (tok.k === "block") el.onclick = () => {
      const target = document.getElementById("b" + tok.s);
      if (target) target.scrollIntoView({behavior: "smooth", block: "center"});
    };
    span.appendChild(el);
    span.appendChild(document.createTextNode(" "));
  }
  return span;
}

function refLine(xref) {
  return `${hex(xref.from)} <span class="kind">${xref.kind}` +
    (xref.in ? " in " + xref.in : "") + "</span>";
}

function render(data) {
  current = data;
  dataAt = null;
  $("title").textContent = data.name + "  " + hex(data.addr);
  $("hint").style.display = "none";

  const code = $("code");
  code.innerHTML = "";
  setCursor(null);

  for (const block of data.blocks) {
    const div = document.createElement("div");
    div.className = "block";
    div.id = "b" + block.id;

    const head = document.createElement("div");
    head.className = "blockhead";
    head.textContent = `block ${block.id} @ ${hex(block.addr)}` +
      (block.entry ? " (entry)" : "") +
      (block.preds.length ? "  from " + block.preds.join(" ") : "");
    div.appendChild(head);

    // References go where you are already looking, at the label, the way IDA
    // has put them for thirty years -- not in a panel off to the side.
    for (const xref of (block.xrefs || [])) {
      const row = document.createElement("div");
      row.className = "xref";
      row.innerHTML = "; XREF " + refLine(xref);
      row.onclick = () => go(String(xref.from));
      div.appendChild(row);
    }

    for (const comment of block.comments) {
      const c = document.createElement("div");
      c.className = "bcmt";
      c.textContent = "; " + comment;
      div.appendChild(c);
    }

    for (const line of block.lines) {
      const row = document.createElement("div");
      row.className = "line";
      row.dataset.addr = line.addr;
      row.onclick = () => setCursor(row);

      const addr = document.createElement("span");
      addr.className = "addr";
      addr.textContent = hex(line.addr);
      addr.title = "look at the bytes here";
      addr.onclick = (e) => { e.stopPropagation(); showDataAt(line.addr); };
      row.appendChild(addr);
      row.appendChild(renderTokens(line));

      if (line.comments.length) {
        const c = document.createElement("span");
        c.className = "cmt";
        c.textContent = "  ; " + line.comments.join("; ");
        row.appendChild(c);
      }
      div.appendChild(row);
    }
    code.appendChild(div);
  }

  code.scrollTop = 0;
  loadFunctions($("filter").value);
}

// -------------------------------------------------------------- the editing

async function rename(id) {
  if (!current) return;
  const name = await askText("rename " + id + " to", id);
  if (!name) return;
  await ask(`rename ${current.addr} ${id} ${name}`);
  go(String(current.addr), false);
}

async function renameFunction() {
  if (!current) return;
  const name = await askText("rename function to", current.name);
  if (!name) return;
  await ask(`rename ${current.addr} - ${name}`);
  go(String(current.addr), false);
}

async function setType(id) {
  if (!current) return;
  const type = await askText("type for " + id, "int32_t");
  if (!type) return;
  await ask(`settype ${current.addr} ${id} ${type}`);
  go(String(current.addr), false);
}

async function comment() {
  const at = cursorAddr();
  if (at === null || at === undefined) return;
  const text = await askText("comment at " + hex(at), "");
  if (text === null) return;
  await ask(`comment ${at} ${text}`);
  if (current) go(String(current.addr), false);
}

async function showXrefs() {
  const at = cursorAddr();
  if (at === null || at === undefined) return;
  const data = await ask("xrefs " + at);
  askChoice("xrefs to " + hex(at), (data.refs || []).map((ref) => ({
    text: refLine(ref),
    go: () => go(String(ref.from)),
  })));
}

// --------------------------------------------------------------- data items
//
// Not a hex dump. What you want to know about a word of data is what it *is*:
// a literal pool is a run of words each of which is an address or a constant,
// and sixteen bytes to a row tells you none of that.

function showDataAt(address) { ask(`data ${address} 64`).then(showData); }

function showData(data) {
  dataAt = data.addr;
  $("datahead").textContent = "data " + hex(data.addr) +
    (data.code ? " (in code)" : "");

  const side = $("side");
  side.innerHTML = "";

  for (const item of (data.items || [])) {
    const row = document.createElement("div");
    row.className = "item";

    let text = `<span class="addr">${hex(item.addr).padEnd(10)}</span>`;
    if (item.label) text += `<span class="tgt">${item.label}</span>  `;

    if (item.kind === "string") {
      text += `<span class="str">"${item.text}"</span>`;
    } else {
      text += `<span class="val">${hex(item.value).padStart(10)}</span>`;
      if (item.target)
        text += `  <span class="n">-&gt;</span> <span class="tgt">${item.target}</span>`;
      else if (item.points)
        text += `  <span class="n">-&gt; ${item.points}</span>`;
    }
    if (item.xrefs && item.xrefs.length)
      text += `  <span class="n">(${item.xrefs.length} xref)</span>`;

    row.innerHTML = text;
    row.onclick = () => {
      if (item.kind === "word" && item.points) go(String(item.value));
      else if (item.xrefs && item.xrefs.length)
        askChoice("xrefs to " + hex(item.addr), item.xrefs.map((ref) => ({
          text: refLine(ref), go: () => go(String(ref.from)),
        })));
    };
    side.appendChild(row);
  }

  if (!(data.items || []).length)
    side.innerHTML = '<div class="hint">nothing readable here</div>';

  const more = document.createElement("div");
  more.className = "item n";
  more.textContent = "  more ▾";
  more.onclick = () => showDataAt(data.end);
  side.appendChild(more);
}

// ------------------------------------------------------------------ the keys

document.onkeydown = async (e) => {
  if (e.target.tagName === "INPUT") return;
  if (e.ctrlKey || e.metaKey || e.altKey) return;

  const keys = {
    g: async () => {
      const where = await askText("jump to (address or name)", "");
      if (where && !(await go(where))) openModal("nothing at " + where);
    },
    x: showXrefs,
    n: () => (selected ? rename(selected) : renameFunction()),
    y: () => selected && setType(selected),
    ";": comment,
    d: () => showDataAt(cursorAddr()),
    j: () => moveCursor(1),
    k: () => moveCursor(-1),
    ArrowDown: () => moveCursor(1),
    ArrowUp: () => moveCursor(-1),
    Escape: back,
    Enter: () => selected && go(selected),
    "/": () => $("filter").focus(),
  };

  const act = keys[e.key];
  if (!act) return;
  e.preventDefault();
  act();
};

$("filter").oninput = (e) => loadFunctions(e.target.value);
$("filter").onkeydown = (e) => { if (e.key === "Escape") e.target.blur(); };
$("modal").onclick = (e) => { if (e.target.id === "modal") closeModal(); };
$("code").onclick = () => highlight(null);

loadFunctions("");
$("side").innerHTML =
  '<div class="hint">click an address in the listing, or press d, to look at ' +
  'the bytes there. constants that land in the image are clickable: on ARM ' +
  'that is the literal pool.</div>';

// Open where the program does. `go` asks for a listing first and falls back
// to data, so an entry that is not code still lands somewhere useful.
ask("info").then((info) => {
  $("title").textContent = info.describe || "ddd";
  if (info.entry || info.base) go(String(info.entry || info.base), false);
});
</script>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    analyser = None

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)

        if url.path == "/":
            return self.reply("text/html; charset=utf-8", PAGE.encode())

        if url.path == "/api":
            query = urllib.parse.parse_qs(url.query)
            command = (query.get("cmd") or [""])[0]
            if not command:
                return self.reply("application/json", b'{"error":"no command"}')

            answer = self.analyser.ask(command)
            return self.reply("application/json", json.dumps(answer).encode())

        self.send_error(404)

    def reply(self, kind, body):
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # the console is for the analyser's own diagnostics


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)

    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True, help="binary to analyse")
    parser.add_argument("--sleigh-poc",
                        default=os.path.join(root, "build/linux/x86_64/debug/sleigh_poc"))
    parser.add_argument("--specs", default=os.path.join(root, "specs"))
    parser.add_argument("--project", default=None,
                        help="project file (default: <file>.ddd)")
    parser.add_argument("--sla", default=None,
                        help="architecture for a file with no container "
                             "(firmware); a bare name resolves in --specs")
    parser.add_argument("--region", default=None,
                        help="comma-separated begin:end:spec regions, for an "
                             "image that is not all one architecture")
    parser.add_argument("--base", default=None,
                        help="address the image is loaded at")
    parser.add_argument("--port", type=int, default=8722)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    if not os.path.exists(args.sleigh_poc):
        print(f"no analyser at {args.sleigh_poc} -- build it with `xmake`",
              file=sys.stderr)
        return 2
    if not os.path.exists(args.file):
        print(f"no such file: {args.file}", file=sys.stderr)
        return 2

    project = args.project or (args.file + ".ddd")
    extra = []
    if args.sla:
        extra.append("--sla=" + args.sla)
    if args.region:
        extra.append("--region=" + args.region)
    if args.base:
        extra.append("--base=" + args.base)

    Handler.analyser = Analyser(args.sleigh_poc, args.file, args.specs, project,
                                extra)

    server = http.server.ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"ddd on http://{args.host}:{args.port}/  ({args.file}, project {project})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        Handler.analyser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
