"""Keep hosted console output structural; retain redacted detail in encrypted diagnostics."""
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import threading
import traceback
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MAX_LOG = 64 * 1024
KEEP_RUNS = 20
N = r"[0-9]{1,7}"
METRICS = [re.compile(p) for p in (
    rf"{N} recipient\(s\)",
    rf"collection: {N} feeds, {N} items in {N}\.[0-9]s",
    rf"collection check: {N} of {N} feeds",
    rf"selection evaluation: {N} labelled, {N} pending, {N} attempts",
    rf"publication dates: {N} cached, {N} fetched, {N} deferred by budget",
    rf"sent {N} of {N} new items",
    rf"subscribers: \+{N} -{N}",
    rf"pre-judged {N} item\(s\) for the [0-9]{{2}}:00 digest",
    rf"classified {N} item\(s\) with Gemini; dropped {N} as off-topic, {N} as duplicates(?: \(partly\))?",
    rf"instant alerts: {N} candidate\(s\), sent {N}, {N} dropped by Gemini(?: quietly)?",
    rf"review snapshot: {N} items",
    rf"ok: last run {N} minutes ago",
    rf"state cache: (?:open|seal) succeeded \({N} files, encrypted\)",
)]


def error_kind(text):
    for phrase, kind in (("today's Gemini budget is used up", "BudgetExhausted"),
                         ("temporary rest period", "TemporaryRest"),
                         ("classification time budget reached", "DeadlineExceeded")):
        if phrase in text:
            return kind
    match = re.search(r"\bHTTP(?: Error)?[ :]+([1-5][0-9]{2})\b", text)
    if match:
        return "HTTP " + match[1]
    for kind in ("TimeoutError", "URLError", "JSONDecodeError", "ValueError", "OSError", "TelegramError"):
        if kind in text:
            return kind
    if re.search(r"timed? ?out|timeout", text, re.I):
        return "TimeoutError"
    return "Error"


def public_line(text, stream="stderr"):
    """An allowlist, not a redaction regex: arbitrary titles/responses never pass through."""
    text = text.strip()
    if any(pattern.fullmatch(text) for pattern in METRICS):
        return text
    if stream == "stdout" and text in ("changed", "unchanged"):
        return text  # the subscriber backup shell consumes these exact status words
    match = re.fullmatch(rf"summaries from article pages: ({N}) of ({N})(?: \(.*\))?", text)
    if match:
        return f"summaries from article pages: {match[1]} of {match[2]}"
    if text.startswith("ai models: "):
        count = sum(int(n) for n in re.findall(r"\bx([0-9]{1,4})\b", text))
        return f"ai requests answered: {count}"
    if text.startswith("warning:") or text.startswith("error:"):
        level = "error" if text.startswith("error:") else "warning"
        source = re.match(r"warning: source ([0-9]{1,5})(?: failed:|:)", text)
        if source:
            context = f"source {source[1]}"
        elif "translation failed" in text:
            context = "translation"
        elif "classification" in text:
            context = "classification"
        elif text.startswith("warning: Gemini"):
            context = "AI request"
        elif "subscriber" in text:
            context = "subscriber operation"
        elif "state" in text or "cache" in text:
            context = "state operation"
        elif "chat " in text or "message" in text or "owner" in text:
            context = "delivery"
        else:
            context = "operation"
        return f"{level}: {context} ({error_kind(text)})"
    if text.startswith("stale:"):
        return "warning: timer stale"
    match = re.fullmatch(r"최근 봇에 메시지를 보낸 채팅 ([0-9]{1,7})개", text)
    if match:
        return f"telegram chats: {match[1]}"
    if text == "night notice sent":
        return text
    if text in ("Private summary diagnostic saved; no AI or Telegram calls were made.",
                "Administrator layout preview sent; no subscriber or news state was accessed."):
        return "diagnostic operation completed"
    return None


def redact(text):
    for name, value in os.environ.items():
        if re.search(r"TOKEN|KEY|SECRET|PASSWORD|CHAT(?:_IDS?)?$", name) and len(value) >= 4:
            for form in (value, urllib.parse.quote(value, safe=""), json.dumps(value)[1:-1]):
                text = text.replace(form, "[REDACTED]")
    text = re.sub(r"\bAIza[0-9A-Za-z_-]{35}\b", "[REDACTED]", text)
    text = re.sub(r"\b[0-9]{8,12}:[A-Za-z0-9_-]{30,50}\b", "[REDACTED]", text)
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b", "[REDACTED]", text)
    return text


class Capture:
    def __init__(self):
        self.lock, self.parts, self.size, self.issue = threading.Lock(), [], 0, False

    def add(self, text):
        with self.lock:
            self.parts.append(text)
            self.size += len(text)
            while self.size > 2 * MAX_LOG and len(self.parts) > 1:
                self.size -= len(self.parts.pop(0))
            if len(self.parts) == 1 and self.size > 2 * MAX_LOG:
                self.parts[0] = self.parts[0][-2 * MAX_LOG:]
                self.size = len(self.parts[0])


class PublicStream(io.TextIOBase):
    def __init__(self, original, capture, name):
        self.original, self.capture, self.name, self.pending = original, capture, name, ""
        self.lock = threading.RLock()

    def write(self, text):
        with self.lock:
            self.capture.add(text)
            self.pending += text
            if self.pending.lstrip().startswith(("warning:", "error:")):
                self.capture.issue = True
            while "\n" in self.pending:
                line, self.pending = self.pending.split("\n", 1)
                self.emit(line)
            if len(self.pending) > MAX_LOG:
                self.pending = ""  # an oversized unstructured line is private only
        return len(text)

    def emit(self, line):
        if line.lstrip().startswith(("warning:", "error:")):
            self.capture.issue = True
        if line.startswith("summaries from article pages:") and " failed," in line:
            self.capture.issue = True
        safe = public_line(line, self.name)
        if safe:
            self.original.write(safe + "\n")
            self.original.flush()

    def flush(self):
        with self.lock:
            if self.pending:
                self.emit(self.pending)
                self.pending = ""
            self.original.flush()


def save_diagnostics(capture, code, label):
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    test = bool(os.environ.get("SECNEWS_ONLY_CHATS"))
    persistent = label == "secnews" and not test
    state = Path(os.environ.get("SECNEWS_STATE", ".state/seen.json"))
    journal = (state.with_name("private-diagnostics.json") if persistent else
               Path(".diagnostics-work/private-diagnostics.json"))
    try:
        old = json.loads(journal.read_text(encoding="utf-8"))
        runs = old.get("runs", []) if isinstance(old, dict) else []
        runs = runs if isinstance(runs, list) else []
    except (OSError, ValueError):
        runs = []
    run = os.environ.get("GITHUB_RUN_ID", "local")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    run = run if re.fullmatch(r"[0-9]{1,20}", run) else "local"
    attempt = attempt if re.fullmatch(r"[0-9]{1,5}", attempt) else "1"
    identity = f"{run}-{attempt}-{label}"
    entry = {"id": identity, "at": datetime.now(timezone.utc).isoformat(), "exit_code": code,
             "log": redact("".join(capture.parts))[-MAX_LOG:]}
    runs = [r for r in runs if isinstance(r, dict) and r.get("id") != identity][-KEEP_RUNS + 1:] + [entry]
    journal.parent.mkdir(parents=True, exist_ok=True)
    temp = journal.with_suffix(".tmp")
    temp.write_text(json.dumps({"v": 1, "runs": runs}, ensure_ascii=False), encoding="utf-8")
    temp.chmod(0o600)
    temp.replace(journal)
    # A failed run never saves production news state. Keep its diagnostics independently,
    # encrypted before artifact upload; successful runtime warnings use the encrypted state cache.
    if code or not persistent or os.environ.get("SECNEWS_VERBOSE"):
        from tools.state_cache import seal
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder)
            (report / "diagnostics.json").write_text(json.dumps(entry, ensure_ascii=False), encoding="utf-8")
            seal(report, Path(".diagnostics-cache") / f"{identity}.enc", token)


def execute(main, label="secnews", drain=None):
    if not os.environ.get("GITHUB_ACTIONS"):
        return main()
    if label not in ("secnews", "backup", "preview", "summary", "chats", "watchdog", "collection", "evaluation"):
        raise ValueError("unknown diagnostic label")
    capture = Capture()
    out, err = PublicStream(sys.stdout, capture, "stdout"), PublicStream(sys.stderr, capture, "stderr")
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            result = main()
            code = result if isinstance(result, int) else 0 if result is None else 1
            if result is not None and not isinstance(result, int):
                capture.add(repr(result))
        except SystemExit as error:
            code = error.code if isinstance(error.code, int) else 1
            if error.code and not isinstance(error.code, int):
                capture.add(str(error.code))
        except BaseException as error:
            code = 130 if isinstance(error, KeyboardInterrupt) else 1
            capture.add(traceback.format_exc())
            err.write(f"error: application failed ({error_kind(type(error).__name__)})\n")
        finally:
            if drain:
                try:
                    drain()
                except Exception:
                    capture.add(traceback.format_exc())
                    capture.issue = True
            out.flush()
            err.flush()
    code = code if 0 <= code <= 255 else 1
    if code:
        print(f"error: worker exited (status {code})", file=sys.stderr)
    if code or capture.issue or label == "chats" or os.environ.get("SECNEWS_VERBOSE"):
        try:
            save_diagnostics(capture, code, label)
        except Exception:
            print("warning: private diagnostic storage failed", file=sys.stderr)
    return code
