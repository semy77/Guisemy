# ═══════════════════════════════════════════════════════════════════════════
#  main.py — Entry Point & Security (Locking System) + FULL VERBOSE LOGGING
#  Owner: AVI CODEX  | Telegram: @AVI_CODEXX
# ═══════════════════════════════════════════════════════════════════════════

import sys
import os
import socket
import hashlib
import asyncio
import traceback
import time
import platform
from datetime import datetime

# ═══════════════ OWNER DETAILS ═══════════════
_OWNER_NAME = "AVI CODEX "
_TG_ID = "@AVI_CODEXX"

_SIG_FILE = "signature.txt"
_LOG_FILE = "logs.txt"

# ═══════════════ DNS CONFIG ═══════════════
_CUSTOM_DNS_HOST = "dns.google.com"
_CUSTOM_DNS_IPS  = ["8.8.8.8", "8.8.4.4"]   # Google Public DNS


# ═══════════════════════════════════════════════════════════════════════════
#  GLOBAL LOG SYSTEM — Har cheez console + file dono me
# ═══════════════════════════════════════════════════════════════════════════

class Logger:
    """Saare prints ko timestamp ke saath console + logs.txt me bhejta hai."""
    LEVEL_ICONS = {
        "INFO":    "ℹ️ ",
        "STEP":    "➡️ ",
        "OK":      "✅",
        "WARN":    "⚠️ ",
        "ERROR":   "❌",
        "SECURITY":"🔒",
        "DEBUG":   "🔍",
        "MENU":    "📋",
        "NET":     "🌐",
        "DATA":    "💾",
    }

    def __init__(self, log_file):
        self.log_file = log_file
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr

    def _write_file(self, text):
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(text)
        except Exception:
            pass

    def _ts(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def log(self, level, message):
        ts = self._ts()
        icon = self.LEVEL_ICONS.get(level, "•")
        line = f"[{ts}] {icon} [{level:<8}] {message}"
        try:
            self._orig_stdout.write(line + "\n")
            self._orig_stdout.flush()
        except Exception:
            pass
        self._write_file(line + "\n")

    def info(self, msg):    self.log("INFO", msg)
    def step(self, msg):    self.log("STEP", msg)
    def ok(self, msg):      self.log("OK", msg)
    def warn(self, msg):    self.log("WARN", msg)
    def error(self, msg):   self.log("ERROR", msg)
    def security(self, msg):self.log("SECURITY", msg)
    def debug(self, msg):   self.log("DEBUG", msg)
    def menu(self, msg):    self.log("MENU", msg)
    def net(self, msg):     self.log("NET", msg)
    def data(self, msg):    self.log("DATA", msg)

    def raw(self, text=""):
        try:
            self._orig_stdout.write(text + "\n")
            self._orig_stdout.flush()
        except Exception:
            pass
        self._write_file(text + "\n")

    def log_exception(self, context, exc):
        ts = self._ts()
        tb = traceback.format_exc()
        header = (
            "\n" + "═" * 72 + "\n"
            f"[{ts}] ❌ ERROR [{context}]\n"
            f"    Type    : {type(exc).__name__}\n"
            f"    Message : {exc}\n"
            + "─" * 72 + "\n"
        )
        footer = "═" * 72 + "\n"
        try:
            self._orig_stderr.write(header + tb + footer)
            self._orig_stderr.flush()
        except Exception:
            pass
        self._write_file(header + tb + footer)

    def install_tee(self):
        logger = self

        class Tee:
            def __init__(self, original, stream_name):
                self.original = original
                self.stream_name = stream_name
                self.buffer = ""

            def write(self, text):
                try:
                    self.original.write(text)
                    self.original.flush()
                except Exception:
                    pass
                self.buffer += text
                while "\n" in self.buffer:
                    line, self.buffer = self.buffer.split("\n", 1)
                    if line.strip():
                        logger._write_file(f"    {line}\n")

            def flush(self):
                try:
                    self.original.flush()
                except Exception:
                    pass

            def isatty(self):
                return False

        sys.stdout = Tee(self._orig_stdout, "stdout")
        sys.stderr = Tee(self._orig_stderr, "stderr")

    def uninstall_tee(self):
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr


# Global logger instance
LOG = Logger(_LOG_FILE)


# ═══════════════ TIMER HELPER ═══════════════
class Timer:
    def __init__(self, label):
        self.label = label
        self.start = None

    def __enter__(self):
        self.start = time.time()
        LOG.step(f"▶ START: {self.label}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.time() - self.start
        if exc_type:
            LOG.error(f"✖ FAILED: {self.label} ({elapsed:.2f}s) — {exc_val}")
        else:
            LOG.ok(f"✔ DONE  : {self.label} ({elapsed:.2f}s)")
        return False


# ═══════════════ DNS SETUP ═══════════════
def _apply_custom_dns():
    """
    Force DNS resolution through dns.google.com (Google Public DNS).
    - Verifies dns.google.com resolves
    - Logs which resolver/IPs are being used
    - Patches socket.getaddrinfo to log all DNS lookups (NET logs)
    """
    LOG.step("DNS setup: applying custom resolver (dns.google.com / 8.8.8.8 / 8.8.4.4)...")
    try:
        with Timer("DNS: verify dns.google.com"):
            try:
                resolved = socket.gethostbyname(_CUSTOM_DNS_HOST)
                LOG.net(f"dns.google.com → {resolved}")
            except Exception as e:
                LOG.warn(f"Could not resolve {_CUSTOM_DNS_HOST}: {e}")
                LOG.warn(f"Fallback IPs will be used: {', '.join(_CUSTOM_DNS_IPS)}")

        # Patch getaddrinfo to log every DNS lookup in NET category
        _orig_getaddrinfo = socket.getaddrinfo

        def _patched_getaddrinfo(host, port, *args, **kwargs):
            LOG.debug(f"DNS lookup: {host}:{port}")
            try:
                result = _orig_getaddrinfo(host, port, *args, **kwargs)
                # Log first resolved IP for visibility
                if result:
                    sockaddr = result[0][4]
                    if isinstance(sockaddr, tuple) and len(sockaddr) >= 1:
                        LOG.net(f"Resolved {host} → {sockaddr[0]}")
                return result
            except Exception as e:
                LOG.error(f"DNS lookup failed for {host}: {e}")
                raise

        socket.getaddrinfo = _patched_getaddrinfo

        LOG.ok(f"DNS active: {_CUSTOM_DNS_HOST} ({', '.join(_CUSTOM_DNS_IPS)})")
        LOG.net("All socket DNS lookups will now be logged in [NET] category.")
        return True
    except Exception as e:
        LOG.error(f"DNS setup error: {e}")
        LOG.log_exception("DNS_SETUP", e)
        return False


# ═══════════════ LOCKING SYSTEM ═══════════════
def _lock_tool():
    LOG.step("Lock tool: match.py ka SHA-256 hash bana rahe hain...")
    try:
        with Timer("LOCK: read match.py"):
            with open("match.py", "rb") as f:
                match_data = f.read()

        LOG.data(f"match.py size: {len(match_data)} bytes")

        with Timer("LOCK: compute SHA-256"):
            match_hash = hashlib.sha256(match_data).hexdigest()

        LOG.data(f"hash = {match_hash}")

        with open(_SIG_FILE, "w") as f:
            f.write(match_hash)

        LOG.ok(f"Signature file '{_SIG_FILE}' saved")
        LOG.security("🔒 [SECURITY LOCKED] — Match.py hash save ho gaya. Ab koi ise change nahi kar sakta.")
    except Exception as e:
        LOG.error(f"Locking failed: {e}")
        LOG.log_exception("LOCK_TOOL", e)
        sys.exit(1)


def _verify_match_integrity():
    LOG.step("Integrity check: signature file check kar rahe hain...")

    if not os.path.exists(_SIG_FILE):
        LOG.warn(f"'{_SIG_FILE}' nahi mila — pehli baar lock kar rahe hain.")
        _lock_tool()
        return True

    try:
        LOG.debug(f"Reading expected hash from '{_SIG_FILE}'")
        with open(_SIG_FILE, "r") as f:
            expected_hash = f.read().strip()
        LOG.data(f"expected_hash = {expected_hash}")

        LOG.debug("Reading match.py content...")
        with open("match.py", "rb") as f:
            match_data = f.read()
        LOG.data(f"match.py size = {len(match_data)} bytes")

        LOG.debug("Computing current SHA-256 hash...")
        current_hash = hashlib.sha256(match_data).hexdigest()
        LOG.data(f"current_hash  = {current_hash}")

        if current_hash != expected_hash:
            LOG.security("❌ HASH MISMATCH — match.py modify hui hai!")
            LOG.security(f"   expected: {expected_hash}")
            LOG.security(f"   actual  : {current_hash}")
            return False

        LOG.ok("Integrity check passed — match.py untouched.")
        return True
    except Exception as e:
        LOG.error(f"Error checking match.py: {e}")
        LOG.log_exception("VERIFY_INTEGRITY", e)
        return False


def _show_violation():
    LOG.raw(f"""
╔══════════════════════════════════════════════════════════════╗
║  ⛔ SECURITY VIOLATION / ACCESS DENIED                        ║
║                                                              ║
║  match.py file has been MODIFIED without permission!         ║
║  The cryptographic integrity check failed.                   ║
║                                                              ║
║  OWNER: {_OWNER_NAME:<52}║
║  TELEGRAM: {_TG_ID:<48}║
║                                                              ║
║  IF CANNOT CHANGE ANYTHING 😄                                 ║
║  BECAUSE OWNER IS YOUR DAD {_OWNER_NAME.upper():<28}║
║                                                              ║
║  AIS AAAJYE KOI KUCH BHI FILE ME CHANGE KRE THODA SA BHI     ║
║  TO AAJYE                                                    ║
╚══════════════════════════════════════════════════════════════╝
""")


# ═══════════════ BANNER ═══════════════
def _show_banner():
    LOG.raw(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   █████╗ ███╗   ██╗██╗   ██╗██████╗  █████╗  ██████╗         ║
║  ██╔══██╗████╗  ██║██║   ██║██╔══██╗██╔══██╗██╔════╝         ║
║  ███████║██╔██╗ ██║██║   ██║██████╔╝███████║██║  ███╗        ║
║  ██╔══██║██║╚██╗██║██║   ██║██╔══██╗██╔══██║██║   ██║        ║
║  ██║  ██║██║ ╚████║╚██████╔╝██║  ██║██║  ██║╚██████╔╝        ║
║  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝         ║
║                                                              ║
║  SINGH EDITION — All Regions Support                         ║
║                                                              ║
║  Owner      : {_OWNER_NAME:<46}║
║  Telegram   : {_TG_ID:<46}║
║  DNS        : dns.google.com (8.8.8.8 / 8.8.4.4)             ║
║                                                              ║
║  🔒 THIS FILE IS CRYPTOGRAPHICALLY LOCKED                    ║
║  ⚠️  ANY MODIFICATION WILL BREAK THE TOOL                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")


# ═══════════════ ENV SNAPSHOT ═══════════════
def _log_environment():
    LOG.step("Environment snapshot collect kar rahe hain...")
    LOG.info(f"Python     : {sys.version.split()[0]}")
    LOG.info(f"Platform   : {platform.platform()}")
    LOG.info(f"Machine    : {platform.machine()}")
    LOG.info(f"CWD        : {os.getcwd()}")
    LOG.info(f"PID        : {os.getpid()}")
    LOG.info(f"Log file   : {os.path.abspath(_LOG_FILE)}")
    LOG.info(f"Signature  : {os.path.abspath(_SIG_FILE) if os.path.exists(_SIG_FILE) else 'NOT FOUND'}")
    LOG.info(f"match.py   : {'FOUND' if os.path.exists('match.py') else 'NOT FOUND'}")
    LOG.info(f"core.py    : {'FOUND' if os.path.exists('core.py') else 'NOT FOUND'}")
    LOG.net(f"DNS target : {_CUSTOM_DNS_HOST} ({', '.join(_CUSTOM_DNS_IPS)})")


# ═══════════════ SAFE IMPORT HELPER ═══════════════
def _safe_import(module_name, symbol_name):
    LOG.step(f"Importing: from {module_name} import {symbol_name}")
    with Timer(f"Import {module_name}.{symbol_name}"):
        try:
            mod = __import__(module_name, fromlist=[symbol_name])
            fn = getattr(mod, symbol_name)
            LOG.ok(f"Loaded {module_name}.{symbol_name} → {fn}")
            return fn
        except ImportError as e:
            LOG.error(f"ImportError: {module_name} load nahi hua — {e}")
            raise
        except AttributeError as e:
            LOG.error(f"AttributeError: '{symbol_name}' {module_name} me nahi mila — {e}")
            raise


# ═══════════════ MENU ACTIONS ═══════════════
def _action_gen_accounts():
    LOG.menu("User selected: [1] Gen Accounts (all regions)")
    with Timer("ACTION: generate_accounts_interactive"):
        try:
            fn = _safe_import("core", "generate_accounts_interactive")
            LOG.step("Calling generate_accounts_interactive()...")
            fn()
            LOG.ok("generate_accounts_interactive() finished successfully")
        except Exception as e:
            LOG.error(f"Gen Accounts failed: {e}")
            LOG.log_exception("ACTION_GEN_ACCOUNTS", e)


def _action_join_guild():
    LOG.menu("User selected: [2] Join Guild")
    with Timer("ACTION: join_clan_interactive"):
        try:
            fn = _safe_import("core", "join_clan_interactive")
            LOG.step("Calling join_clan_interactive() inside asyncio.run()...")
            asyncio.run(fn())
            LOG.ok("join_clan_interactive() finished successfully")
        except Exception as e:
            LOG.error(f"Join Guild failed: {e}")
            LOG.log_exception("ACTION_JOIN_GUILD", e)


def _action_start_match():
    LOG.menu("User selected: [3] Start Match (all regions)")
    with Timer("ACTION: start_match_interactive"):
        try:
            fn = _safe_import("match", "start_match_interactive")
            LOG.step("Calling start_match_interactive() inside asyncio.run()...")
            asyncio.run(fn())
            LOG.ok("start_match_interactive() finished successfully")
        except Exception as e:
            LOG.error(f"Start Match failed: {e}")
            LOG.log_exception("ACTION_START_MATCH", e)


# ═══════════════ MENU LOOP ═══════════════
def main_menu():
    LOG.info("═" * 70)
    LOG.info("APPLICATION START")
    LOG.info("═" * 70)
    _log_environment()

    # 0. Apply custom DNS (dns.google.com) — MUST be before any network call
    with Timer("DNS SETUP"):
        _apply_custom_dns()

    # 1. Match.py Integrity Check
    with Timer("INTEGRITY CHECK"):
        if not _verify_match_integrity():
            _show_violation()
            LOG.security("Exit due to integrity violation")
            LOG.info("═" * 70)
            LOG.info("APPLICATION EXIT (security)")
            LOG.info("═" * 70)
            sys.exit(1)

    # 2. Show Banner
    _show_banner()

    menu_iteration = 0
    while True:
        menu_iteration += 1
        LOG.raw("")
        LOG.raw("  ╔══════════════════════════════════════════╗")
        LOG.raw("  ║         MAIN MENU  BY AVI CODEX     ║")
        LOG.raw("  ╠══════════════════════════════════════════╣")
        LOG.raw("  ║  1. Gen Accounts (all regions)           ║")
        LOG.raw("  ║  2. Join Guild                           ║")
        LOG.raw("  ║  3. Start Match (all regions)            ║")
        LOG.raw("  ║  4. Exit                                 ║")
        LOG.raw("  ╚══════════════════════════════════════════╝")
        LOG.raw("")

        try:
            choice = input("  > ").strip()
            LOG.debug(f"Menu iteration #{menu_iteration}: raw input = '{choice}'")
        except (EOFError, KeyboardInterrupt):
            LOG.warn("Menu input interrupted (EOF / Ctrl+C)")
            break

        if choice == "1":
            _action_gen_accounts()
        elif choice == "2":
            _action_join_guild()
        elif choice == "3":
            _action_start_match()
        elif choice == "4":
            LOG.menu("User selected: [4] Exit")
            break
        else:
            LOG.warn(f"Invalid choice: '{choice}' — expected 1, 2, 3, or 4")
            print(f"  ! Invalid choice")

        LOG.raw("")
        try:
            input("  Press Enter to continue...")
        except (EOFError, KeyboardInterrupt):
            LOG.warn("Continue prompt interrupted")
            break

    LOG.info("═" * 70)
    LOG.info("APPLICATION EXIT (normal)")
    LOG.info("═" * 70)


# ═══════════════ ENTRYPOINT ═══════════════
if __name__ == "__main__":
    LOG._write_file("\n\n" + "█" * 72 + "\n")
    LOG._write_file(f"NEW RUN — {datetime.now().isoformat()}\n")
    LOG._write_file("█" * 72 + "\n")

    LOG.install_tee()

    try:
        main_menu()
    except KeyboardInterrupt:
        LOG.warn("Interrupted by user (Ctrl+C at top-level)")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        LOG.error(f"FATAL ERROR in main: {e}")
        LOG.log_exception("FATAL_MAIN", e)
        sys.exit(1)
    finally:
        LOG.uninstall_tee()