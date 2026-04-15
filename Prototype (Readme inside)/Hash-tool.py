#!/usr/bin/env python3
"""
Mint-Hash Master Suite
Cross-platform GUI frontend for hashcat & John the Ripper.
"""

import os
import sys
import subprocess
import threading
import shutil
import platform
import datetime
import time
import hashlib
import hmac
import secrets
import tempfile
import urllib.request
import urllib.error
import glob

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

import json

import customtkinter as ctk
from tkinter import filedialog, colorchooser, messagebox

# Force dark mode BEFORE any widget is created
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")


# =================================================================
# HELPERS
# =================================================================
def _round_ram(raw_gb: float) -> int:
    """Round raw psutil RAM reading up to the nearest standard DIMM size."""
    standards = [2, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 512]
    for s in standards:
        if raw_gb <= s + 0.5:   # allow a tiny margin for reporting errors
            return s
    return int(raw_gb) + 1


def _exe_dir() -> str:
    """Return the directory of the running script/executable."""
    if getattr(sys, "frozen", False):          # PyInstaller bundle
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


# =================================================================
# 1. CONFIG
# =================================================================
class AppConfig:
    VERSION      = "Beta 1.0"
    REPO_URL     = "https://github.com/TanRequiem/Requiems-john-hash-GUI-cracker"
    UPDATE_URL   = "https://raw.githubusercontent.com/TanRequiem/Requiems-john-hash-GUI-cracker/main/version.txt"
    CHECKSUM_URL = "https://raw.githubusercontent.com/TanRequiem/Requiems-john-hash-GUI-cracker/main/checksum.sha256"
    AUTHOR       = "TanRequiem"
    APP_NAME     = "Requiem's Hash GUI Cracker"

    ROOT_DIR      = _exe_dir()
    DEP_DIR       = os.path.join(ROOT_DIR, "Application Dependencies")
    WORDLISTS_DIR = os.path.join(ROOT_DIR, "Wordlists")
    POTFILE       = os.path.join(ROOT_DIR, "hashcat.potfile")   # same dir as app
    SETTINGS_FILE = os.path.join(ROOT_DIR, "settings.json")

    # Hardware detection — RAM rounded to nearest real DIMM size
    if PSUTIL_OK:
        _raw_ram    = psutil.virtual_memory().total / (1024 ** 3)
        TOTAL_RAM   = _round_ram(_raw_ram)
        _raw_ram_gb = round(_raw_ram, 2)          # actual reading for display
    else:
        TOTAL_RAM   = 8
        _raw_ram_gb = 8.0
    TOTAL_CORES = os.cpu_count() or 4

    # Defaults — overwritten by load_settings()
    power_mode           = "Balanced"
    cpu_cores_limit      = TOTAL_CORES
    gpu_power_percent    = 100
    ram_usage_gb         = TOTAL_RAM
    gui_scale_pct        = 100          # 100 = 1.0x actual CTk scale (the default)
    pot_storage_limit_mb = 50
    dark_mode_active     = True

    color_bg        = "#121212"
    color_frame     = "#1e1e1e"
    color_sub_frame = "#252525"
    color_text      = "#e0e0e0"
    color_term_bg   = "#0a0a0a"
    color_term_text = "#00ff41"
    color_accent    = "#27ae60"
    color_danger    = "#c0392b"
    color_warn      = "#f39c12"
    color_info      = "#2980b9"

    # Theme presets — each fully overrides every color attr
    THEMES = {
        "Mint Green": {
            "color_bg": "#121212", "color_frame": "#1e1e1e", "color_sub_frame": "#252525",
            "color_text": "#e0e0e0", "color_term_bg": "#0a0a0a", "color_term_text": "#00ff41",
            "color_accent": "#27ae60", "color_info": "#2980b9",
            "color_warn": "#f39c12", "color_danger": "#c0392b",
        },
        "Hacker Red": {
            "color_bg": "#0d0000", "color_frame": "#1a0000", "color_sub_frame": "#220000",
            "color_text": "#ffcccc", "color_term_bg": "#050000", "color_term_text": "#ff4444",
            "color_accent": "#c0392b", "color_info": "#8e2222",
            "color_warn": "#e67e22", "color_danger": "#7b241c",
        },
        "Ocean Blue": {
            "color_bg": "#0a0f1a", "color_frame": "#0f1b2e", "color_sub_frame": "#152438",
            "color_text": "#cce4ff", "color_term_bg": "#050d18", "color_term_text": "#00cfff",
            "color_accent": "#2980b9", "color_info": "#1a6a9e",
            "color_warn": "#f39c12", "color_danger": "#c0392b",
        },
        "Purple Void": {
            "color_bg": "#0d0010", "color_frame": "#180020", "color_sub_frame": "#200030",
            "color_text": "#e8ccff", "color_term_bg": "#080010", "color_term_text": "#da8fff",
            "color_accent": "#8e44ad", "color_info": "#6c3483",
            "color_warn": "#d35400", "color_danger": "#922b21",
        },
        "Bone White": {
            "color_bg": "#f0ece4", "color_frame": "#e4dfd6", "color_sub_frame": "#d8d3ca",
            "color_text": "#1a1a1a", "color_term_bg": "#1e1e1e", "color_term_text": "#00cc44",
            "color_accent": "#5d8233", "color_info": "#2471a3",
            "color_warn": "#d68910", "color_danger": "#a93226",
        },
    }

    HASH_MODES = [
        "MD5 (0)", "MD5-APR (1600)", "SHA-1 (100)", "SHA-224 (1300)",
        "SHA-256 (1400)", "SHA-384 (10800)", "SHA-512 (1700)",
        "NTLM (1000)", "NetNTLMv2 (5600)", "bcrypt (3200)",
        "WPA2-PMKID (22000)", "MySQL4.1 (300)", "SHA-256(Unix) (7400)",
        "Keccak-256 (17300)", "RIPEMD-160 (6000)",
    ]

    # Persisted settings keys
    _PERSIST_KEYS = [
        "power_mode", "cpu_cores_limit", "gpu_power_percent", "ram_usage_gb",
        "gui_scale_pct", "pot_storage_limit_mb", "dark_mode_active",
        "color_bg", "color_frame", "color_sub_frame", "color_text",
        "color_term_bg", "color_term_text", "color_accent",
        "color_danger", "color_warn", "color_info",
    ]

    @classmethod
    def initialize(cls):
        os.makedirs(cls.DEP_DIR, exist_ok=True)
        os.makedirs(cls.WORDLISTS_DIR, exist_ok=True)
        os.environ["PATH"] = cls.DEP_DIR + os.pathsep + os.environ.get("PATH", "")
        # Create potfile if first run
        if not os.path.exists(cls.POTFILE):
            open(cls.POTFILE, "w").close()
        cls.load_settings()

    @classmethod
    def load_settings(cls):
        """Load persisted settings from JSON. Missing keys fall back to class defaults."""
        if not os.path.exists(cls.SETTINGS_FILE):
            return
        try:
            with open(cls.SETTINGS_FILE, "r") as f:
                data = json.load(f)
            for key in cls._PERSIST_KEYS:
                if key in data:
                    setattr(cls, key, data[key])
        except Exception:
            pass   # corrupt file — just use defaults

    @classmethod
    def save_settings(cls):
        """Persist current runtime settings to JSON."""
        data = {k: getattr(cls, k) for k in cls._PERSIST_KEYS}
        try:
            with open(cls.SETTINGS_FILE, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    @classmethod
    def actual_scale(cls) -> float:
        """Convert gui_scale_pct to actual CTk scale. 100% = 1.0x (default)."""
        return round(cls.gui_scale_pct / 100, 3)

    @classmethod
    def get_wordlists(cls):
        return sorted(glob.glob(os.path.join(cls.WORDLISTS_DIR, "*.txt")))

    @classmethod
    def auto_learn_mode(cls, entry):
        if not any(entry in m for m in cls.HASH_MODES):
            cls.HASH_MODES.append(entry)
            return True
        return False

    @classmethod
    def integrity_check(cls) -> tuple[bool, str]:
        """
        Compare a SHA-256 of this script against the published checksum in the repo.
        Returns (ok: bool, message: str).
        Runs in a background thread — never blocks the UI.
        """
        try:
            script_path = os.path.abspath(__file__) if not getattr(sys, "frozen", False) else sys.executable
            with open(script_path, "rb") as f:
                local_hash = hashlib.sha256(f.read()).hexdigest()
            with urllib.request.urlopen(cls.CHECKSUM_URL, timeout=8) as resp:
                remote_hash = resp.read().decode().strip().split()[0].lower()
            if local_hash == remote_hash:
                return True, "Integrity verified — application is authentic."
            else:
                return False, (
                    "⚠️  INTEGRITY WARNING\n\n"
                    "This copy does not match the published checksum.\n"
                    "If you did not modify the source yourself, you may have\n"
                    "downloaded from an unofficial source.\n\n"
                    f"Expected: {remote_hash[:16]}…\n"
                    f"Got:      {local_hash[:16]}…\n\n"
                    f"Download the official version from:\n{cls.REPO_URL}"
                )
        except urllib.error.URLError:
            return True, "Integrity check skipped — no internet connection."
        except Exception as e:
            return True, f"Integrity check skipped — {e}"


# =================================================================
# 2. MASK REFERENCE
# =================================================================
MASK_REFERENCE = """
+=============================================+
|         HASHCAT MASK CHARSETS              |
+=============================================+
|  ?l  = abcdefghijklmnopqrstuvwxyz          |
|  ?u  = ABCDEFGHIJKLMNOPQRSTUVWXYZ          |
|  ?d  = 0123456789                          |
|  ?s  = space !"#$%&'()*+,-./:;<=>?@       |
|        [\\]^_`{|}~                          |
|  ?a  = ?l + ?u + ?d + ?s  (all printable) |
|  ?b  = 0x00 - 0xff  (all bytes)            |
+=============================================+
|  Examples:                                 |
|  ?a?a?a?a?a?a  -> 6-char all printable    |
|  ?u?l?l?l?d?d  -> Cap+4lower+2digit       |
|  ?d?d?d?d      -> 4-digit PIN             |
|  ?l?l?l?l?d?d?s -> 4low+2dig+symbol       |
+=============================================+
"""


# =================================================================
# 3. BACKEND
# =================================================================
class StorageEngine:
    @staticmethod
    def get_pot_size_mb():
        if os.path.exists(AppConfig.POTFILE):
            return round(os.path.getsize(AppConfig.POTFILE) / (1024 * 1024), 2)
        return 0.0

    @staticmethod
    def purge_pot():
        if os.path.exists(AppConfig.POTFILE):
            os.remove(AppConfig.POTFILE)
            return True
        return False

    @staticmethod
    def parse_pot():
        results = []
        if not os.path.exists(AppConfig.POTFILE):
            return results
        try:
            with open(AppConfig.POTFILE, "r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if ":" in line:
                        h, pw = line.split(":", 1)
                        results.append((h, pw))
        except Exception:
            pass
        return results


class AnalysisEngine:
    CONVERTERS = {
        ".pdf":  "pdf2john",
        ".zip":  "zip2john",
        ".rar":  "rar2john",
        ".7z":   "7z2john",
        ".docx": "office2john",
        ".xlsx": "office2john",
    }

    @classmethod
    def identify(cls, hash_string):
        if not shutil.which("hashid"):
            return None, None
        try:
            result = subprocess.run(
                ["hashid", "-m", hash_string],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if "Hashcat Mode:" in line:
                    mode = line.split("Hashcat Mode:")[1].strip().strip("]").strip()
                    return f"Auto ({mode})", mode
        except Exception:
            pass
        return None, None


class ForgeEngine:
    ALGORITHMS = ["MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
                  "SHA3-256", "SHA3-512", "BLAKE2b", "BLAKE2s"]

    @staticmethod
    def hash_text(text, algorithm, salt="", iterations=1):
        algo = algorithm.lower().replace("-", "").replace("_", "")
        data = (salt + text).encode("utf-8")
        try:
            if algo == "blake2b":
                h = hashlib.blake2b(data)
            elif algo == "blake2s":
                h = hashlib.blake2s(data)
            else:
                h = hashlib.new(algo, data)
            result = h.hexdigest()
            for _ in range(iterations - 1):
                result = hashlib.new(algo, result.encode()).hexdigest()
            return result
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def generate_salt(length=16):
        return secrets.token_hex(length // 2)

    @staticmethod
    def hmac_hash(text, key, algorithm):
        algo = algorithm.lower().replace("-", "")
        try:
            h = hmac.new(key.encode(), text.encode(), algo)
            return h.hexdigest()
        except Exception as e:
            return f"Error: {e}"


class UpdateEngine:
    @staticmethod
    def get_tool_version(tool):
        binary = shutil.which(tool)
        if not binary:
            return "NOT FOUND", None
        try:
            r = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5)
            lines = (r.stdout or r.stderr or "").splitlines()
            ver = lines[0].strip() if lines else "Unknown"
            return ver, binary
        except Exception as e:
            return f"Error ({e})", binary

    @staticmethod
    def check_remote_version():
        """
        Fetch the latest release tag from GitHub via the public API.
        Returns the tag string, "OFFLINE", "NO_RELEASES", or "Error: ...".
        """
        api_url = (
            "https://api.github.com/repos/TanRequiem/"
            "Requiems-john-hash-GUI-cracker/releases/latest"
        )
        req = urllib.request.Request(
            api_url,
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "RequiemHashGUI"}
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
                return data.get("tag_name", "Unknown")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return "NO_RELEASES"
            return f"Error: HTTP {e.code}"
        except urllib.error.URLError:
            return "OFFLINE"
        except Exception as e:
            return f"Error: {e}"


# =================================================================
# 4. MAIN APP
# =================================================================
class MintHashMaster(ctk.CTk):
    def __init__(self):
        super().__init__()
        AppConfig.initialize()
        ctk.set_widget_scaling(AppConfig.actual_scale())

        self.title(f"{AppConfig.APP_NAME}  |  {AppConfig.VERSION}")
        self.geometry("1380x1000")
        self.resizable(True, True)          # never lock corners
        self.configure(fg_color=AppConfig.color_bg)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)

        self.active_proc = None
        self.stop_requested = False

        # Ctrl+A select-all for every CTkEntry in the app
        self.bind_all("<Control-a>", self._select_all)
        self.bind_all("<Control-A>", self._select_all)

        self._build_ui()
        self._apply_theme()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(900, self._sunday_check)
        self.after(1500, lambda: threading.Thread(target=self._run_integrity_check, daemon=True).start())

    def _select_all(self, event):
        """Ctrl+A — select all text in the focused entry or textbox."""
        w = event.widget
        try:
            if hasattr(w, "select_range"):      # tk.Entry / CTkEntry inner widget
                w.select_range(0, "end")
                w.icursor("end")
            elif hasattr(w, "tag_add"):         # tk.Text / CTkTextbox inner widget
                w.tag_add("sel", "1.0", "end")
        except Exception:
            pass
        return "break"

    def _on_close(self):
        AppConfig.save_settings()
        self.destroy()

    def _run_integrity_check(self):
        ok, msg = AppConfig.integrity_check()
        if not ok:
            self.after(0, lambda: messagebox.showwarning("Integrity Warning", msg))

    # ----------------------------------------------------------------
    # TOP LEVEL UI
    # ----------------------------------------------------------------
    def _build_ui(self):
        self.main_tabs = ctk.CTkTabview(
            self,
            fg_color=AppConfig.color_frame,
            segmented_button_fg_color=AppConfig.color_frame,
            segmented_button_selected_color=AppConfig.color_accent,
            segmented_button_unselected_color="#2a2a2a",
            segmented_button_selected_hover_color="#2ecc71",
            corner_radius=12,
        )
        self.main_tabs.grid(row=0, column=0, padx=20, pady=(20, 4), sticky="nsew")

        self.tab_attack   = self.main_tabs.add("⚡  ATTACK CENTER")
        self.tab_forge    = self.main_tabs.add("⚗️  FORGE")
        self.tab_settings = self.main_tabs.add("⚙️  SYSTEM SETTINGS")

        for tab in (self.tab_attack, self.tab_forge, self.tab_settings):
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=1)

        # Status bar
        self.status_bar = ctk.CTkLabel(
            self, text="  Ready", anchor="w",
            font=("Consolas", 11), text_color="#666",
            fg_color=AppConfig.color_frame,
        )
        self.status_bar.grid(row=1, column=0, sticky="ew")

        self._build_attack_tab()
        self._build_forge_tab()
        self._build_settings_tab()
        self._update_status_bar()

    # ----------------------------------------------------------------
    # ATTACK CENTER
    # ----------------------------------------------------------------
    def _build_attack_tab(self):
        root = self.tab_attack
        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(0, weight=1)

        # Outer scrollable container — everything lives inside here.
        # When the window is made very small nothing disappears; it just scrolls.
        outer = ctk.CTkScrollableFrame(
            root, fg_color="transparent",
            scrollbar_button_color=AppConfig.color_accent,
        )
        outer.grid(row=0, column=0, sticky="nsew")
        outer.grid_columnconfigure(0, weight=1)
        # The log box needs its own dedicated row with a fixed min height
        outer.grid_rowconfigure(5, weight=0)

        # Alias so all _panel() calls below go into outer, not root
        root = outer

        # Target
        p_target = self._panel(root, row=0, pady=(20, 8))
        p_target.grid_columnconfigure(0, weight=1)
        self.target_entry = ctk.CTkEntry(
            p_target, placeholder_text="Enter hash string or file path...",
            height=44, font=("Consolas", 13),
            fg_color=AppConfig.color_sub_frame, border_color=AppConfig.color_accent,
            text_color=AppConfig.color_text,
        )
        self.target_entry.grid(row=0, column=0, padx=15, pady=12, sticky="ew")
        ctk.CTkButton(p_target, text="📁 Browse", width=110,
                       fg_color="#2a2a2a", hover_color=AppConfig.color_accent,
                       command=self._browse_target).grid(row=0, column=1, padx=(0, 8))
        ctk.CTkButton(p_target, text="🔍 Identify", width=100,
                       fg_color="#2a2a2a", hover_color="#3a3a3a",
                       command=self._identify).grid(row=0, column=2, padx=(0, 8))
        # Red ✕ clears the hash/path input field
        ctk.CTkButton(
            p_target, text="✕", width=32, height=32,
            font=("Arial", 13, "bold"),
            corner_radius=16,
            fg_color=AppConfig.color_danger,
            hover_color="#e74c3c",
            text_color="white",
            command=lambda: self.target_entry.delete(0, "end"),
        ).grid(row=0, column=3, padx=(0, 15))

        # Config
        p_cfg = self._panel(root, row=1, pady=6)
        # minsize prevents columns collapsing when window is resized small
        for col, minsz in enumerate([250, 250, 220, 280]):
            p_cfg.grid_columnconfigure(col, minsize=minsz, weight=0)
        ctk.CTkLabel(p_cfg, text="Hash Mode:", text_color="#888", font=("Arial", 11)
                      ).grid(row=0, column=0, padx=(15, 4), pady=4, sticky="w")
        self.mode_combo = ctk.CTkComboBox(
            p_cfg, values=AppConfig.HASH_MODES, width=230,
            fg_color=AppConfig.color_sub_frame, border_color="#444",
            text_color=AppConfig.color_text,
        )
        self.mode_combo.grid(row=1, column=0, padx=15, pady=(0, 14))

        ctk.CTkLabel(p_cfg, text="Attack Mode:", text_color="#888", font=("Arial", 11)
                      ).grid(row=0, column=1, padx=(10, 4), pady=4, sticky="w")
        self.atk_combo = ctk.CTkComboBox(
            p_cfg,
            values=["Wordlist (0)", "Combination (1)", "Brute Force / Mask (3)",
                    "Hybrid WL+Mask (6)", "Hybrid Mask+WL (7)"],
            width=230, fg_color=AppConfig.color_sub_frame,
            border_color="#444", text_color=AppConfig.color_text,
        )
        self.atk_combo.grid(row=1, column=1, padx=10, pady=(0, 14))

        ctk.CTkLabel(p_cfg, text="Engine:", text_color="#888", font=("Arial", 11)
                      ).grid(row=0, column=2, padx=(10, 4), pady=4, sticky="w")
        self.engine_var = ctk.StringVar(value="hashcat")
        ef = ctk.CTkFrame(p_cfg, fg_color="transparent")
        ef.grid(row=1, column=2, padx=10, pady=(0, 14), sticky="w")
        ctk.CTkRadioButton(ef, text="Hashcat 🐈", variable=self.engine_var, value="hashcat",
                            fg_color=AppConfig.color_accent, text_color=AppConfig.color_text).pack(side="left", padx=6)
        ctk.CTkRadioButton(ef, text="John 🔪", variable=self.engine_var, value="john",
                            fg_color=AppConfig.color_accent, text_color=AppConfig.color_text).pack(side="left", padx=6)

        ctk.CTkLabel(p_cfg, text="Extra Flags:", text_color="#888", font=("Arial", 11)
                      ).grid(row=0, column=3, padx=(10, 4), pady=4, sticky="w")
        self.extra_flags_entry = ctk.CTkEntry(
            p_cfg, placeholder_text="--force  -O  --session=myrun  etc.",
            width=260, fg_color=AppConfig.color_sub_frame,
            border_color="#444", text_color=AppConfig.color_text,
        )
        self.extra_flags_entry.grid(row=1, column=3, padx=10, pady=(0, 14))

        # Wordlist / Mask
        p_wl = self._panel(root, row=2, pady=6)
        p_wl.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(p_wl, text="Wordlist / Mask:", text_color="#888", width=130, anchor="w"
                      ).grid(row=0, column=0, padx=15)
        self.wl_entry = ctk.CTkEntry(
            p_wl,
            placeholder_text="Leave blank to use all Wordlists/*.txt  |  or enter mask: ?a?a?a?a?a?a",
            fg_color=AppConfig.color_sub_frame, border_color="#444",
            text_color=AppConfig.color_text,
        )
        self.wl_entry.grid(row=0, column=1, padx=8, pady=12, sticky="ew")
        ctk.CTkButton(p_wl, text="Browse", width=80, fg_color="#2a2a2a",
                       hover_color=AppConfig.color_accent,
                       command=lambda: self._browse_into(self.wl_entry)).grid(row=0, column=2, padx=4)
        ctk.CTkButton(p_wl, text="?", width=36, font=("Arial", 14, "bold"),
                       fg_color="#333", hover_color="#555",
                       command=self._show_mask_help).grid(row=0, column=3, padx=(4, 8))
        self.wl_count_label = ctk.CTkLabel(p_wl, text="", text_color="#666", font=("Consolas", 11))
        self.wl_count_label.grid(row=0, column=4, padx=(0, 6))
        ctk.CTkButton(p_wl, text="📂 Wordlists Folder", width=140, fg_color="#2a2a2a",
                       hover_color="#3a3a3a",
                       command=self._open_wordlists_folder).grid(row=0, column=5, padx=(0, 15))
        self._refresh_wl_count()

        # Controls
        p_ctrl = ctk.CTkFrame(root, fg_color="transparent")
        p_ctrl.grid(row=3, column=0, padx=20, pady=6, sticky="ew")
        for i in range(5):
            p_ctrl.grid_columnconfigure(i, weight=1)

        self.btn_run = ctk.CTkButton(
            p_ctrl, text="⚡ START ATTACK", height=52,
            font=("Arial", 15, "bold"),
            fg_color=AppConfig.color_accent, hover_color="#2ecc71",
            command=self._start_thread,
        )
        self.btn_run.grid(row=0, column=0, padx=4, sticky="ew")

        self.btn_stop = ctk.CTkButton(
            p_ctrl, text="🛑 STOP", height=52,
            font=("Arial", 15, "bold"),
            fg_color=AppConfig.color_danger, hover_color="#e74c3c",
            state="disabled", command=self._stop_engine,
        )
        self.btn_stop.grid(row=0, column=1, padx=4, sticky="ew")

        ctk.CTkButton(p_ctrl, text="🍯 Gold Pot", height=52,
                       fg_color="#7d6608", hover_color=AppConfig.color_warn,
                       command=self._view_pot).grid(row=0, column=2, padx=4, sticky="ew")

        ctk.CTkButton(p_ctrl, text="📋 Copy Last Line", height=52,
                       fg_color="#2a2a2a", hover_color="#3a3a3a",
                       command=self._copy_last_result).grid(row=0, column=3, padx=4, sticky="ew")

        ctk.CTkButton(p_ctrl, text="🗑️ Clear Log", height=52,
                       fg_color="#2a2a2a", hover_color="#3a3a3a",
                       command=lambda: self.log_box.delete("1.0", "end")).grid(row=0, column=4, padx=4, sticky="ew")

        # Log — wrap in a frame so we can overlay the clear button with place()
        log_frame = ctk.CTkFrame(root, fg_color="transparent")
        log_frame.grid(row=5, column=0, padx=20, pady=(6, 20), sticky="nsew")
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)

        self.log_box = ctk.CTkTextbox(
            log_frame, font=("Consolas", 13), corner_radius=10,
            border_width=2, wrap="word", height=320,
            fg_color=AppConfig.color_term_bg,
            text_color=AppConfig.color_term_text,
            border_color=AppConfig.color_accent,
        )
        self.log_box.grid(row=0, column=0, sticky="nsew")

        self._print("")
        self._print("╔══════════════════════════════════════════════════════╗")
        self._print(f"║       {AppConfig.APP_NAME:<46}║")
        self._print(f"║       Version {AppConfig.VERSION:<42}║")
        self._print(f"║       by {AppConfig.AUTHOR:<47}║")
        self._print("╠══════════════════════════════════════════════════════╣")
        self._print("║  Drop a hash in the field above and hit Start.       ║")
        self._print("║  Add wordlists to the Wordlists/ folder to begin.    ║")
        self._print("╚══════════════════════════════════════════════════════╝")
        self._print("")

    # ----------------------------------------------------------------
    # FORGE TAB
    # ----------------------------------------------------------------
    def _build_forge_tab(self):
        root = self.tab_forge
        root.grid_rowconfigure(0, weight=1)
        sf = self._scrollframe(root)

        self._section(sf, "⚗️  Hash Forge  —  Hashing & Encoding  (results NOT saved to Gold Pot)")

        ctk.CTkLabel(sf, text="Plaintext Input:", text_color="#aaa", anchor="w").pack(fill="x", padx=10, pady=(4, 2))
        self.forge_input = ctk.CTkTextbox(sf, height=80, font=("Consolas", 13),
                                           fg_color=AppConfig.color_sub_frame,
                                           text_color=AppConfig.color_text,
                                           border_width=1, border_color="#444")
        self.forge_input.pack(fill="x", padx=10, pady=(0, 12))

        opts = ctk.CTkFrame(sf, fg_color="transparent")
        opts.pack(fill="x", padx=10, pady=4)

        ctk.CTkLabel(opts, text="Algorithm:", text_color="#aaa").grid(row=0, column=0, padx=(0, 6))
        self.forge_algo = ctk.CTkComboBox(opts, values=ForgeEngine.ALGORITHMS, width=160,
                                           fg_color=AppConfig.color_sub_frame,
                                           border_color="#444", text_color=AppConfig.color_text)
        self.forge_algo.set("SHA-256")
        self.forge_algo.grid(row=0, column=1, padx=(0, 20))

        ctk.CTkLabel(opts, text="Iterations:", text_color="#aaa").grid(row=0, column=2, padx=(0, 6))
        self.forge_iter = ctk.CTkEntry(opts, width=70, fg_color=AppConfig.color_sub_frame,
                                        border_color="#444", text_color=AppConfig.color_text)
        self.forge_iter.insert(0, "1")
        self.forge_iter.grid(row=0, column=3, padx=(0, 20))

        self.forge_hmac_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(opts, text="HMAC Mode", variable=self.forge_hmac_var,
                         fg_color=AppConfig.color_accent, text_color=AppConfig.color_text,
                         command=self._toggle_hmac_ui).grid(row=0, column=4, padx=(0, 10))

        salt_row = ctk.CTkFrame(sf, fg_color="transparent")
        salt_row.pack(fill="x", padx=10, pady=6)
        salt_row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(salt_row, text="Salt:", text_color="#aaa", width=60, anchor="w").grid(row=0, column=0)
        self.forge_salt_entry = ctk.CTkEntry(
            salt_row, placeholder_text="Optional salt (prepended to input)",
            fg_color=AppConfig.color_sub_frame, border_color="#444", text_color=AppConfig.color_text,
        )
        self.forge_salt_entry.grid(row=0, column=1, padx=8, sticky="ew")
        ctk.CTkButton(salt_row, text="🎲 Generate Salt", width=140,
                       fg_color="#2a2a2a", hover_color=AppConfig.color_accent,
                       command=self._gen_salt).grid(row=0, column=2, padx=4)

        self.hmac_row = ctk.CTkFrame(sf, fg_color="transparent")
        self.hmac_row.pack(fill="x", padx=10, pady=2)
        self.hmac_row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(self.hmac_row, text="HMAC Key:", text_color="#aaa", width=80, anchor="w").grid(row=0, column=0)
        self.forge_hmac_key = ctk.CTkEntry(
            self.hmac_row, placeholder_text="Secret HMAC key",
            fg_color=AppConfig.color_sub_frame, border_color="#444", text_color=AppConfig.color_text,
        )
        self.forge_hmac_key.grid(row=0, column=1, padx=8, sticky="ew")
        self.hmac_row.pack_forget()

        ctk.CTkButton(sf, text="⚗️ FORGE HASH", height=50, font=("Arial", 15, "bold"),
                       fg_color=AppConfig.color_info, hover_color="#3498db",
                       command=self._run_forge).pack(anchor="w", padx=10, pady=14)

        out_h = ctk.CTkFrame(sf, fg_color="transparent")
        out_h.pack(fill="x", padx=10, pady=(4, 2))
        ctk.CTkLabel(out_h, text="Output:", text_color="#aaa", anchor="w").pack(side="left")
        ctk.CTkButton(out_h, text="📋 Copy", width=70, height=26,
                       fg_color="#2a2a2a", hover_color="#444",
                       command=self._copy_forge_output).pack(side="right")

        self.forge_output = ctk.CTkTextbox(sf, height=140, font=("Consolas", 13),
                                            fg_color=AppConfig.color_term_bg,
                                            text_color=AppConfig.color_term_text,
                                            border_width=1, border_color=AppConfig.color_info)
        self.forge_output.pack(fill="x", padx=10, pady=(0, 20))

        self._section(sf, "🔎  Hash Verifier  —  check if a plaintext matches a known hash")
        comp_row = ctk.CTkFrame(sf, fg_color="transparent")
        comp_row.pack(fill="x", padx=10, pady=4)
        comp_row.grid_columnconfigure((1, 3), weight=1)

        ctk.CTkLabel(comp_row, text="Plaintext:", text_color="#aaa", width=80).grid(row=0, column=0, padx=(0, 6))
        self.verify_plain = ctk.CTkEntry(comp_row, fg_color=AppConfig.color_sub_frame,
                                          border_color="#444", text_color=AppConfig.color_text)
        self.verify_plain.grid(row=0, column=1, padx=(0, 20), sticky="ew")

        ctk.CTkLabel(comp_row, text="Known Hash:", text_color="#aaa", width=90).grid(row=0, column=2, padx=(0, 6))
        self.verify_hash_entry = ctk.CTkEntry(comp_row, fg_color=AppConfig.color_sub_frame,
                                               border_color="#444", text_color=AppConfig.color_text)
        self.verify_hash_entry.grid(row=0, column=3, padx=(0, 12), sticky="ew")

        ctk.CTkButton(comp_row, text="Verify", width=90,
                       fg_color=AppConfig.color_accent, hover_color="#2ecc71",
                       command=self._run_verify).grid(row=0, column=4)

        self.verify_result = ctk.CTkLabel(sf, text="", font=("Arial", 14, "bold"), anchor="w")
        self.verify_result.pack(fill="x", padx=10, pady=6)

    # ----------------------------------------------------------------
    # SETTINGS
    # ----------------------------------------------------------------
    def _build_settings_tab(self):
        root = self.tab_settings
        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(0, weight=1)

        self.s_tabs = ctk.CTkTabview(
            root,
            fg_color=AppConfig.color_frame,
            segmented_button_fg_color=AppConfig.color_frame,
            segmented_button_selected_color=AppConfig.color_info,
            segmented_button_unselected_color="#2a2a2a",
            corner_radius=10,
        )
        self.s_tabs.grid(row=0, column=0, padx=12, pady=12, sticky="nsew")

        self.st_gen = self.s_tabs.add("General")
        self.st_vis = self.s_tabs.add("Customization")
        self.st_inf = self.s_tabs.add("Updates & Info")

        for st in (self.st_gen, self.st_vis, self.st_inf):
            st.grid_columnconfigure(0, weight=1)
            st.grid_rowconfigure(0, weight=1)

        self._build_general_tab()
        self._build_customization_tab()
        self._build_info_tab()

    def _build_general_tab(self):
        sf = self._scrollframe(self.st_gen)
        self._section(sf, "🚀 Resource Governor")

        # Scale slider: integer steps of 10. 100 = 1.5x actual (user baseline = "1")
        self.gui_label = self._lbl(sf, f"GUI Scaling: {AppConfig.gui_scale_pct}%  (1.0x at default)")
        s = ctk.CTkSlider(sf, from_=100, to=200,
                           number_of_steps=10,        # 100,110,120…200
                           button_color=AppConfig.color_accent)
        s.set(AppConfig.gui_scale_pct)
        s.bind("<ButtonRelease-1>", lambda e: self._update_scale(s.get()))
        s.pack(fill="x", padx=(10, 220), pady=(0, 18))

        self._lbl(sf, "Power Mode:")
        self.pwr_menu = ctk.CTkOptionMenu(sf, values=["Battery Saver", "Balanced", "High Performance"],
                                           fg_color=AppConfig.color_sub_frame, button_color=AppConfig.color_accent,
                                           command=lambda v: [setattr(AppConfig, "power_mode", v), AppConfig.save_settings()])
        self.pwr_menu.set(AppConfig.power_mode)
        self.pwr_menu.pack(anchor="w", padx=10, pady=(0, 18))

        self.cpu_label = self._lbl(sf, f"CPU Cores: {AppConfig.cpu_cores_limit} / {AppConfig.TOTAL_CORES}")
        s_cpu = ctk.CTkSlider(sf, from_=1, to=AppConfig.TOTAL_CORES, button_color=AppConfig.color_accent,
                                command=lambda v: [setattr(AppConfig, "cpu_cores_limit", int(v)),
                                                   self.cpu_label.configure(text=f"CPU Cores: {int(v)} / {AppConfig.TOTAL_CORES}")])
        s_cpu.set(AppConfig.TOTAL_CORES)
        s_cpu.pack(fill="x", padx=(10, 220), pady=(0, 18))

        self.gpu_label = self._lbl(sf, f"GPU Power Draw: {AppConfig.gpu_power_percent}%")
        s_gpu = ctk.CTkSlider(sf, from_=10, to=100, button_color=AppConfig.color_accent,
                                command=lambda v: [setattr(AppConfig, "gpu_power_percent", int(v)),
                                                   self.gpu_label.configure(text=f"GPU Power Draw: {int(v)}%")])
        s_gpu.set(AppConfig.gpu_power_percent)
        s_gpu.pack(fill="x", padx=(10, 220), pady=(0, 18))

        self.ram_label = self._lbl(sf, f"RAM Limit: {AppConfig.ram_usage_gb} GB")
        s_ram = ctk.CTkSlider(sf, from_=1, to=max(AppConfig.TOTAL_RAM, 2), button_color=AppConfig.color_accent,
                                command=lambda v: [setattr(AppConfig, "ram_usage_gb", round(v, 1)),
                                                   self.ram_label.configure(text=f"RAM Limit: {round(v, 1)} GB")])
        s_ram.set(AppConfig.TOTAL_RAM)
        s_ram.pack(fill="x", padx=(10, 220), pady=(0, 18))

        self.pot_label = self._lbl(sf, f"Gold Pot Warning: {AppConfig.pot_storage_limit_mb} MB")
        s_pot = ctk.CTkSlider(sf, from_=10, to=500, button_color=AppConfig.color_warn,
                               command=lambda v: [setattr(AppConfig, "pot_storage_limit_mb", int(v)),
                                                  self.pot_label.configure(text=f"Gold Pot Warning: {int(v)} MB")])
        s_pot.set(AppConfig.pot_storage_limit_mb)
        s_pot.pack(fill="x", padx=(10, 220), pady=(0, 18))

        self._section(sf, "🛠️ Quick Actions")
        act = ctk.CTkFrame(sf, fg_color="transparent")
        act.pack(fill="x", padx=10, pady=4)
        ctk.CTkButton(act, text="🗑️ Purge Gold Pot", fg_color=AppConfig.color_danger,
                       hover_color="#e74c3c", command=self._purge_pot).pack(side="left", padx=(0, 10))
        ctk.CTkButton(act, text="📂 Wordlists Folder", fg_color="#2a2a2a", hover_color="#3a3a3a",
                       command=self._open_wordlists_folder).pack(side="left", padx=(0, 10))
        ctk.CTkButton(act, text="📂 Deps Folder", fg_color="#2a2a2a", hover_color="#3a3a3a",
                       command=lambda: self._open_folder(AppConfig.DEP_DIR)).pack(side="left")

    def _build_customization_tab(self):
        sf = self._scrollframe(self.st_vis)

        # ── Built-in Presets ────────────────────────────────────────
        self._section(sf, "🎨 Theme Presets")
        preset_row = ctk.CTkFrame(sf, fg_color="transparent")
        preset_row.pack(fill="x", padx=10, pady=(0, 8))
        for name, vals in AppConfig.THEMES.items():
            ctk.CTkButton(
                preset_row, text=name, width=120,
                fg_color=vals["color_accent"],
                hover_color=vals["color_term_text"],
                text_color="#fff",
                command=lambda v=vals: self._apply_preset(v),
            ).pack(side="left", padx=4)

        # ── Custom Preset Save / Load ───────────────────────────────
        self._section(sf, "💾 Save Custom Preset")
        save_row = ctk.CTkFrame(sf, fg_color=AppConfig.color_sub_frame, corner_radius=8)
        save_row.pack(fill="x", padx=10, pady=(0, 16))
        save_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(save_row, text="Preset Name:", text_color="#aaa", width=110, anchor="w"
                      ).grid(row=0, column=0, padx=12, pady=12)
        self.preset_name_entry = ctk.CTkEntry(
            save_row, placeholder_text="My Custom Theme",
            fg_color=AppConfig.color_bg, border_color="#444",
            text_color=AppConfig.color_text,
        )
        self.preset_name_entry.grid(row=0, column=1, padx=8, pady=12, sticky="ew")
        ctk.CTkButton(save_row, text="💾 Save", width=90,
                       fg_color=AppConfig.color_info, hover_color="#3498db",
                       command=self._save_custom_preset).grid(row=0, column=2, padx=(0, 12))

        # Saved custom presets row (populated at build + after saves)
        self.custom_preset_row = ctk.CTkFrame(sf, fg_color="transparent")
        self.custom_preset_row.pack(fill="x", padx=10, pady=(0, 16))
        self._refresh_custom_preset_buttons()

        # ── Dark Mode Toggle ────────────────────────────────────────
        self._section(sf, "🎨 Manual Color Editor")
        self.dark_switch = ctk.CTkSwitch(
            sf, text="Dark Mode",
            progress_color="#27ae60",   # always green regardless of theme
            button_color="#ffffff",
            button_hover_color="#dddddd",
            command=self._toggle_dark,
        )
        self.dark_switch.select()
        self.dark_switch.pack(anchor="w", padx=10, pady=(0, 16))

        # ── Color rows with live swatch ─────────────────────────────
        self._color_swatch_frames = {}
        for label, attr in [
            ("Main Background",     "color_bg"),
            ("Panel / Frame",       "color_frame"),
            ("Sub-Frame",           "color_sub_frame"),
            ("Global Text",         "color_text"),
            ("Terminal Background", "color_term_bg"),
            ("Terminal Text",       "color_term_text"),
            ("Accent Highlight",    "color_accent"),
            ("Info / Blue",         "color_info"),
            ("Warning / Orange",    "color_warn"),
            ("Danger / Red",        "color_danger"),
        ]:
            row = ctk.CTkFrame(sf, fg_color=AppConfig.color_sub_frame, corner_radius=8)
            row.pack(fill="x", padx=10, pady=4)

            # Live color swatch
            swatch = ctk.CTkFrame(
                row, width=28, height=28, corner_radius=6,
                fg_color=getattr(AppConfig, attr, "#888888"),
            )
            swatch.pack(side="left", padx=(12, 0), pady=10)
            self._color_swatch_frames[attr] = swatch

            ctk.CTkLabel(row, text=label, width=200, anchor="w",
                          text_color=AppConfig.color_text).pack(side="left", padx=10, pady=10)
            ctk.CTkButton(
                row, text="Choose", width=80, fg_color="#333",
                hover_color=AppConfig.color_accent,
                command=lambda a=attr: self._pick_color(a),
            ).pack(side="right", padx=15, pady=8)

        ctk.CTkButton(sf, text="✅ Apply All Visuals", height=46,
                       fg_color=AppConfig.color_accent, hover_color="#2ecc71",
                       command=self._apply_theme).pack(anchor="w", padx=10, pady=24)

    def _build_info_tab(self):
        sf = self._scrollframe(self.st_inf)

        # ── Watermark / About ──────────────────────────────────────
        wm = ctk.CTkFrame(sf, fg_color="#1a1a2e", corner_radius=10, border_width=1, border_color=AppConfig.color_accent)
        wm.pack(fill="x", padx=10, pady=(10, 4))
        ctk.CTkLabel(wm, text=AppConfig.APP_NAME,
                      font=("Arial", 18, "bold"), text_color=AppConfig.color_accent, anchor="w"
                      ).pack(fill="x", padx=18, pady=(14, 2))
        ctk.CTkLabel(wm, text=f"Version {AppConfig.VERSION}  |  by {AppConfig.AUTHOR}",
                      font=("Consolas", 12), text_color="#888", anchor="w"
                      ).pack(fill="x", padx=18, pady=(0, 4))
        ctk.CTkLabel(wm,
                      text="⚠  If you received a version warning, your copy did not match the official\n"
                           "   checksum. Download only from the official repository below.",
                      font=("Arial", 11), text_color="#cc9900", anchor="w", justify="left"
                      ).pack(fill="x", padx=18, pady=(0, 4))
        # Clickable repo link
        repo_lbl = ctk.CTkLabel(
            wm, text=AppConfig.REPO_URL,
            font=("Consolas", 11, "underline"),
            text_color=AppConfig.color_info, anchor="w", cursor="hand2",
        )
        repo_lbl.pack(fill="x", padx=18, pady=(0, 14))
        repo_lbl.bind("<Button-1>", lambda e: self._open_url(AppConfig.REPO_URL))

        # ── System Hardware ─────────────────────────────────────────
        self._section(sf, "🖥️ System Hardware")
        hw = [
            ("OS",          f"{platform.system()} {platform.release()} ({platform.machine()})"),
            ("Hostname",    platform.node()),
            ("Processor",   platform.processor() or platform.machine()),
            ("CPU Cores",   f"{AppConfig.TOTAL_CORES} logical"),
            # Show the rounded (real) amount alongside the raw reading
            ("System RAM",  f"{AppConfig.TOTAL_RAM} GB  (reported: {AppConfig._raw_ram_gb} GB)"),
        ]
        if PSUTIL_OK:
            try:
                vm   = psutil.virtual_memory()
                used = round(vm.used / (1024 ** 3), 2)
                hw += [
                    ("RAM In Use", f"{used} GB / {AppConfig.TOTAL_RAM} GB  ({vm.percent}%)"),
                    ("CPU %",      f"{psutil.cpu_percent(interval=0.3)}%"),
                ]
            except Exception:
                pass
        for k, v in hw:
            self._info_row(sf, k, v)

        # ── Tool Versions ───────────────────────────────────────────
        self._section(sf, "🔧 Tool Versions")
        self.version_labels      = {}
        self.version_path_labels = {}
        for tool in ["hashcat", "john"]:
            row = ctk.CTkFrame(sf, fg_color=AppConfig.color_sub_frame, corner_radius=6)
            row.pack(fill="x", padx=10, pady=3)
            ctk.CTkLabel(row, text=tool.capitalize(), width=100, anchor="w",
                          text_color="#888", font=("Consolas", 12)).pack(side="left", padx=12, pady=8)
            vlbl = ctk.CTkLabel(row, text="Checking…", anchor="w",
                                 text_color=AppConfig.color_term_text, font=("Consolas", 12))
            vlbl.pack(side="left", padx=(0, 16))
            plbl = ctk.CTkLabel(row, text="", anchor="w", text_color="#555", font=("Consolas", 11))
            plbl.pack(side="left")
            self.version_labels[tool]      = vlbl
            self.version_path_labels[tool] = plbl

        threading.Thread(target=self._fetch_versions, daemon=True).start()

        ctk.CTkButton(sf, text="🔄 Refresh Versions", width=180,
                       fg_color="#2a2a2a", hover_color="#3a3a3a",
                       command=lambda: threading.Thread(target=self._fetch_versions, daemon=True).start()
                       ).pack(anchor="w", padx=10, pady=(8, 0))

        # ── Suite Version & Update ──────────────────────────────────
        self._section(sf, "📦 Suite Version")
        self._info_row(sf, "Installed",   AppConfig.VERSION,       val_color=AppConfig.color_accent)

        # Clickable repository row
        repo_row = ctk.CTkFrame(sf, fg_color=AppConfig.color_sub_frame, corner_radius=6)
        repo_row.pack(fill="x", padx=10, pady=3)
        ctk.CTkLabel(repo_row, text="Repository", width=150, anchor="w",
                      text_color="#888", font=("Consolas", 12)).pack(side="left", padx=12, pady=8)
        repo_link = ctk.CTkLabel(
            repo_row, text=AppConfig.REPO_URL, anchor="w",
            text_color=AppConfig.color_info,
            font=("Consolas", 12, "underline"), cursor="hand2",
        )
        repo_link.pack(side="left", padx=4)
        repo_link.bind("<Button-1>", lambda e: self._open_url(AppConfig.REPO_URL))

        upd_row = ctk.CTkFrame(sf, fg_color=AppConfig.color_sub_frame, corner_radius=6)
        upd_row.pack(fill="x", padx=10, pady=3)
        ctk.CTkLabel(upd_row, text="Latest Remote", width=150, anchor="w",
                      text_color="#888", font=("Consolas", 12)).pack(side="left", padx=12, pady=8)
        self.latest_ver_label = ctk.CTkLabel(upd_row, text="—", anchor="w",
                                              text_color=AppConfig.color_text, font=("Consolas", 12))
        self.latest_ver_label.pack(side="left")

        # Integrity status row
        integ_row = ctk.CTkFrame(sf, fg_color=AppConfig.color_sub_frame, corner_radius=6)
        integ_row.pack(fill="x", padx=10, pady=3)
        ctk.CTkLabel(integ_row, text="Integrity", width=150, anchor="w",
                      text_color="#888", font=("Consolas", 12)).pack(side="left", padx=12, pady=8)
        self.integrity_label = ctk.CTkLabel(integ_row, text="Pending check…", anchor="w",
                                             text_color="#aaa", font=("Consolas", 12))
        self.integrity_label.pack(side="left")

        # ── Paths ───────────────────────────────────────────────────
        self._section(sf, "📁 Paths")
        self._info_row(sf, "Potfile",     AppConfig.POTFILE,       val_color="#555")
        self._info_row(sf, "Wordlists",   AppConfig.WORDLISTS_DIR, val_color="#555")
        self._info_row(sf, "Deps Folder", AppConfig.DEP_DIR,       val_color="#555")
        self._info_row(sf, "Settings",    AppConfig.SETTINGS_FILE, val_color="#555")

        btn_row = ctk.CTkFrame(sf, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=10)
        ctk.CTkButton(btn_row, text="🌐 Check For Updates", height=44,
                       fg_color=AppConfig.color_info, hover_color="#3498db",
                       command=lambda: threading.Thread(target=self._check_updates, daemon=True).start()
                       ).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_row, text="🔒 Re-run Integrity Check", height=44,
                       fg_color="#2a2a2a", hover_color="#444",
                       command=lambda: threading.Thread(target=self._run_integrity_check, daemon=True).start()
                       ).pack(side="left")

    # ----------------------------------------------------------------
    # WIDGET FACTORIES
    # ----------------------------------------------------------------
    def _panel(self, parent, row, pady=(8, 6)):
        f = ctk.CTkFrame(parent, corner_radius=10, fg_color=AppConfig.color_frame)
        f.grid(row=row, column=0, padx=20, pady=pady, sticky="ew")
        f.grid_columnconfigure(0, weight=1)
        return f

    def _scrollframe(self, parent):
        sf = ctk.CTkScrollableFrame(parent, fg_color=AppConfig.color_frame,
                                     scrollbar_button_color=AppConfig.color_accent)
        sf.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        sf.grid_columnconfigure(0, weight=1)
        return sf

    def _section(self, parent, text):
        ctk.CTkLabel(parent, text=text, font=("Arial", 16, "bold"),
                      text_color=AppConfig.color_text, anchor="w").pack(fill="x", padx=10, pady=(18, 4))
        ctk.CTkFrame(parent, height=1, fg_color="#333").pack(fill="x", padx=10, pady=(0, 10))

    def _lbl(self, parent, text):
        lbl = ctk.CTkLabel(parent, text=text, anchor="w", text_color="#bbb", font=("Arial", 12))
        lbl.pack(fill="x", padx=10, pady=(6, 2))
        return lbl

    def _info_row(self, parent, key, val, val_color=None):
        row = ctk.CTkFrame(parent, fg_color=AppConfig.color_sub_frame, corner_radius=6)
        row.pack(fill="x", padx=10, pady=3)
        ctk.CTkLabel(row, text=key, width=150, anchor="w",
                      text_color="#888", font=("Consolas", 12)).pack(side="left", padx=12, pady=8)
        ctk.CTkLabel(row, text=val, anchor="w", wraplength=800,
                      text_color=val_color or AppConfig.color_text,
                      font=("Consolas", 12)).pack(side="left", padx=4)

    # ----------------------------------------------------------------
    # THEME
    # ----------------------------------------------------------------
    def _apply_theme(self):
        self.configure(fg_color=AppConfig.color_bg)
        self.main_tabs.configure(
            fg_color=AppConfig.color_frame,
            segmented_button_fg_color=AppConfig.color_frame,
            segmented_button_selected_color=AppConfig.color_accent,
            segmented_button_unselected_color="#2a2a2a",
        )
        try:
            self.s_tabs.configure(
                fg_color=AppConfig.color_frame,
                segmented_button_fg_color=AppConfig.color_frame,
                segmented_button_selected_color=AppConfig.color_info,
            )
        except Exception:
            pass
        # Log box — fg, text, border AND scrollbar buttons
        self.log_box.configure(
            fg_color=AppConfig.color_term_bg,
            text_color=AppConfig.color_term_text,
            border_color=AppConfig.color_accent,
            scrollbar_button_color=AppConfig.color_accent,
            scrollbar_button_hover_color=AppConfig.color_term_text,
        )
        self.btn_run.configure(fg_color=AppConfig.color_accent, hover_color=AppConfig.color_accent)
        self.btn_stop.configure(fg_color=AppConfig.color_danger)
        self.status_bar.configure(fg_color=AppConfig.color_frame, text_color="#666")

    def _apply_preset(self, vals):
        for k, v in vals.items():
            setattr(AppConfig, k, v)
        self._apply_theme()
        AppConfig.save_settings()

    def _toggle_dark(self):
        AppConfig.dark_mode_active = bool(self.dark_switch.get())
        if AppConfig.dark_mode_active:
            AppConfig.color_bg    = "#121212"
            AppConfig.color_frame = "#1e1e1e"
            ctk.set_appearance_mode("Dark")
        else:
            AppConfig.color_bg    = "#e8e8e8"
            AppConfig.color_frame = "#d0d0d0"
            ctk.set_appearance_mode("Light")
        self._apply_theme()

    def _pick_color(self, attr):
        result = colorchooser.askcolor(
            color=getattr(AppConfig, attr, "#ffffff"),
            title=f"Choose: {attr}",
        )
        if result and result[1]:
            setattr(AppConfig, attr, result[1])
            # Update the live swatch immediately
            try:
                self._color_swatch_frames[attr].configure(fg_color=result[1])
            except Exception:
                pass

    def _save_custom_preset(self):
        name = self.preset_name_entry.get().strip()
        if not name:
            messagebox.showwarning("No Name", "Enter a name for your preset first.")
            return
        # Build a full snapshot of every color attr
        snapshot = {k: getattr(AppConfig, k) for k in [
            "color_bg", "color_frame", "color_sub_frame", "color_text",
            "color_term_bg", "color_term_text", "color_accent",
            "color_info", "color_warn", "color_danger",
        ]}
        # Load existing custom presets file, merge, save
        custom_file = os.path.join(AppConfig.ROOT_DIR, "custom_presets.json")
        try:
            existing = json.loads(open(custom_file).read()) if os.path.exists(custom_file) else {}
        except Exception:
            existing = {}
        existing[name] = snapshot
        try:
            with open(custom_file, "w") as f:
                json.dump(existing, f, indent=2)
            messagebox.showinfo("Saved", f"Preset '{name}' saved.")
            self.preset_name_entry.delete(0, "end")
            self._refresh_custom_preset_buttons()
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def _refresh_custom_preset_buttons(self):
        """Rebuild the custom preset buttons row from the JSON file."""
        for widget in self.custom_preset_row.winfo_children():
            widget.destroy()
        custom_file = os.path.join(AppConfig.ROOT_DIR, "custom_presets.json")
        if not os.path.exists(custom_file):
            ctk.CTkLabel(
                self.custom_preset_row, text="No saved presets yet.",
                text_color="#555", font=("Arial", 11),
            ).pack(side="left", padx=4)
            return
        try:
            presets = json.loads(open(custom_file).read())
        except Exception:
            return
        for name, vals in presets.items():
            btn_frame = ctk.CTkFrame(self.custom_preset_row, fg_color="transparent")
            btn_frame.pack(side="left", padx=4)
            ctk.CTkButton(
                btn_frame, text=name, width=110,
                fg_color=vals.get("color_accent", "#555"),
                hover_color=vals.get("color_term_text", "#888"),
                text_color="#fff",
                command=lambda v=vals: self._apply_preset(v),
            ).pack()
            # Small delete x under each custom preset button
            ctk.CTkButton(
                btn_frame, text="✕", width=110, height=18,
                font=("Arial", 10), fg_color="#2a2a2a", hover_color=AppConfig.color_danger,
                text_color="#888",
                command=lambda n=name: self._delete_custom_preset(n),
            ).pack(pady=(2, 0))

    def _delete_custom_preset(self, name):
        if not messagebox.askyesno("Delete Preset", f"Delete preset '{name}'?"):
            return
        custom_file = os.path.join(AppConfig.ROOT_DIR, "custom_presets.json")
        try:
            presets = json.loads(open(custom_file).read())
            presets.pop(name, None)
            with open(custom_file, "w") as f:
                json.dump(presets, f, indent=2)
            self._refresh_custom_preset_buttons()
        except Exception as e:
            messagebox.showerror("Delete Error", str(e))

    def _update_scale(self, value):
        pct = round(value / 10) * 10          # snap to nearest 10
        pct = max(100, min(200, pct))
        AppConfig.gui_scale_pct = pct
        actual = AppConfig.actual_scale()
        ctk.set_widget_scaling(actual)
        self.gui_label.configure(text=f"GUI Scaling: {pct}%  ({actual}x)")
        AppConfig.save_settings()

    # ----------------------------------------------------------------
    # ATTACK LOGIC
    # ----------------------------------------------------------------
    def _browse_target(self):
        path = filedialog.askopenfilename()
        if path:
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, path)

    def _browse_into(self, entry):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            entry.delete(0, "end")
            entry.insert(0, path)

    def _refresh_wl_count(self):
        n = len(AppConfig.get_wordlists())
        self.wl_count_label.configure(text=f"({n} .txt in Wordlists/)")

    def _open_wordlists_folder(self):
        self._open_folder(AppConfig.WORDLISTS_DIR)
        self.after(500, self._refresh_wl_count)

    def _open_folder(self, path):
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])

    def _show_mask_help(self):
        win = ctk.CTkToplevel(self)
        win.title("Mask Charset Reference")
        win.geometry("480x340")
        win.configure(fg_color=AppConfig.color_bg)
        win.grab_set()
        tb = ctk.CTkTextbox(win, font=("Consolas", 13),
                             fg_color=AppConfig.color_term_bg,
                             text_color=AppConfig.color_term_text)
        tb.pack(fill="both", expand=True, padx=14, pady=14)
        tb.insert("1.0", MASK_REFERENCE)
        tb.configure(state="disabled")

    def _identify(self):
        target = self.target_entry.get().strip()
        if not target:
            return
        self._print("  Identifying hash...")
        label, mode = AnalysisEngine.identify(target)
        if label and mode:
            matched = False
            for item in self.mode_combo.cget("values"):
                if f"({mode})" in item:
                    self.mode_combo.set(item)
                    matched = True
                    self._print(f"  Hash type matched:  {item}")
                    break
            if not matched:
                new_entry = f"Auto-detected ({mode})"
                AppConfig.auto_learn_mode(new_entry)
                vals = list(self.mode_combo.cget("values"))
                if new_entry not in vals:
                    vals.append(new_entry)
                self.mode_combo.configure(values=vals)
                self.mode_combo.set(new_entry)
                self._print(f"  New mode learned and saved:  {new_entry}")
        else:
            self._print("  Could not identify hash — hashid may not be installed.")

    def _start_thread(self):
        threading.Thread(target=self._engine_main, daemon=True).start()

    def _engine_main(self):
        self.stop_requested = False
        self.btn_run.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        target   = self.target_entry.get().strip()
        engine   = self.engine_var.get()
        mode_str = self.mode_combo.get()
        atk_str  = self.atk_combo.get()
        wl_path  = self.wl_entry.get().strip()
        extra    = self.extra_flags_entry.get().strip().split() if self.extra_flags_entry.get().strip() else []

        if not target:
            self._print("  No hash or file entered.")
            self._reset_buttons(); return

        hc_mode  = mode_str.split("(")[-1].rstrip(")").strip()
        atk_mode = atk_str.split("(")[-1].rstrip(")").strip()
        is_mask  = atk_mode in ("3", "6", "7")

        if not is_mask:
            wordlists = [wl_path] if wl_path and os.path.isfile(wl_path) else AppConfig.get_wordlists()
            if not wordlists:
                self._print("  No wordlists found.  Add .txt files to the Wordlists/ folder.")
                self._reset_buttons(); return
        else:
            wordlists = [wl_path] if wl_path else []

        if engine == "hashcat":
            self._run_hashcat(target, hc_mode, atk_mode, wordlists, extra, is_mask)
        else:
            self._run_john(target, wordlists, extra)

        self._reset_buttons()

    def _run_hashcat(self, target, hc_mode, atk_mode, wordlists, extra, is_mask):
        binary = shutil.which("hashcat") or "hashcat"
        if not binary or not shutil.which("hashcat"):
            self._print("  Hashcat not found.  Place it in the Application Dependencies/ folder.")
            return

        if is_mask:
            mask = wordlists[0] if wordlists else "?a?a?a?a?a?a"
            self._print(f"  Cracking  {target}")
            self._print(f"  Mode      {self.mode_combo.get()}")
            self._print(f"  Attack    Brute Force / Mask  [{mask}]")
            self._print("")
            cmd = [binary, f"-m{hc_mode}", f"-a{atk_mode}", target, mask] + extra
            cracked = self._run_silent(cmd, target)
            if cracked:
                result = self._hashcat_show(binary, hc_mode, target)
                self._display_results(result)
            else:
                self._print("")
                self._print("  Unable to crack — mask exhausted.")
                self._print("")
        else:
            total = len(wordlists)
            self._print(f"  Engine    Hashcat")
            self._print(f"  Mode      {self.mode_combo.get()}")
            self._print(f"  Wordlists {total} file(s) queued")
            self._print("")
            cracked = False
            for idx, wl in enumerate(wordlists, 1):
                if self.stop_requested:
                    self._print("  Stopped by user.")
                    break
                self._print(f"  Wordlist  [{idx}/{total}]  {os.path.basename(wl)}")
                cmd = [binary, f"-m{hc_mode}", f"-a{atk_mode}", target, wl] + extra
                self._run_silent(cmd, target)
                result = self._hashcat_show(binary, hc_mode, target)
                if result:
                    cracked = True
                    self._display_results(result)
                    break

            if not cracked and not self.stop_requested:
                self._print("")
                self._print("  Unable to crack — all wordlists exhausted.")
                self._print("  Try more wordlists, Brute Force mode, or a different hash mode.")
                self._print("")
                self.after(0, lambda t=target, e=extra: self._offer_john_fallback(t, e))

    def _run_john(self, target, wordlists, extra):
        binary = shutil.which("john") or "john"
        if not binary or not shutil.which("john"):
            self._print("  John not found.  Place it in the Application Dependencies/ folder.")
            return

        total = len(wordlists)
        self._print(f"  Engine    John the Ripper")
        self._print(f"  Wordlists {total} file(s) queued")
        self._print("")
        cracked = False
        for idx, wl in enumerate(wordlists, 1):
            if self.stop_requested:
                self._print("  Stopped by user.")
                break
            self._print(f"  Wordlist  [{idx}/{total}]  {os.path.basename(wl)}")
            cmd = [binary, target, f"--wordlist={wl}"] + extra
            self._run_silent(cmd, target)
            result = self._john_show(binary, target)
            if result:
                cracked = True
                self._display_results(result)
                break

        if not cracked and not self.stop_requested:
            self._print("")
            self._print("  Unable to crack — all wordlists exhausted.")
            self._print("")

    def _run_silent(self, cmd, target: str = "") -> bool:
        """
        Run a command silently. Shows a 'Cracking ... please stand by' loading bar
        that updates in-place. Caller uses --show to determine actual result.
        """
        BAR_WIDTH   = 20
        done_flag   = [False]
        tick        = [0]
        # Truncate long hashes for display
        h_disp = (target[:36] + "…") if len(target) > 38 else target

        # Insert the header line then the bar line
        self._print(f"  Cracking  {h_disp}  —  Please stand by")
        self._print(f"  [{'░' * BAR_WIDTH}]  0%")

        bar_line = int(self.log_box.index("end-1c").split(".")[0])

        def _animate():
            while not done_flag[0]:
                time.sleep(0.15)
                tick[0] += 1
                # Bouncing fill that cycles 0→100→0 to show activity without a real %
                pos     = tick[0] % (BAR_WIDTH * 2)
                filled  = pos if pos <= BAR_WIDTH else BAR_WIDTH * 2 - pos
                bar_str = "█" * filled + "░" * (BAR_WIDTH - filled)
                pct     = int((filled / BAR_WIDTH) * 100)
                line    = f"  [{bar_str}]  {pct}%"
                self.log_box.after(0, lambda l=line, ln=bar_line: self._replace_line(ln, l))

        threading.Thread(target=_animate, daemon=True).start()

        try:
            self.active_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.active_proc.wait()
        except FileNotFoundError:
            self._print(f"  Binary not found: {cmd[0]}")
        except Exception as e:
            self._print(f"  Error: {e}")
        finally:
            done_flag[0] = True
            self.active_proc = None

        # Replace bar line with a clean "done" indicator
        self.log_box.after(0, lambda ln=bar_line: self._replace_line(
            ln, f"  [{'█' * BAR_WIDTH}]  Done"))
        return True

    def _replace_line(self, line_number: int, new_text: str):
        """Replace an entire log line in-place."""
        try:
            self.log_box.delete(f"{line_number}.0", f"{line_number}.end")
            self.log_box.insert(f"{line_number}.0", new_text)
        except Exception:
            pass

    def _hashcat_show(self, binary: str, hc_mode: str, target: str) -> list[tuple[str, str]]:
        """
        Run `hashcat -m{mode} {hash} --show` and return list of (hash, password) pairs.
        hashcat --show reads from the potfile, so it works even for file targets.
        """
        try:
            r = subprocess.run(
                [binary, f"-m{hc_mode}", target, "--show"],
                capture_output=True, text=True, timeout=15
            )
            results = []
            for line in r.stdout.splitlines():
                line = line.strip()
                if ":" in line:
                    h, pw = line.split(":", 1)
                    results.append((h.strip(), pw.strip()))
            return results
        except Exception:
            return []

    def _john_show(self, binary: str, target: str) -> list[tuple[str, str]]:
        """Run `john --show {target}` and return (hash, password) pairs."""
        try:
            r = subprocess.run(
                [binary, "--show", target],
                capture_output=True, text=True, timeout=15
            )
            results = []
            for line in r.stdout.splitlines():
                if ":" in line and not line.startswith("0 "):
                    parts = line.split(":")
                    if len(parts) >= 2:
                        results.append((parts[0].strip(), parts[1].strip()))
            return results
        except Exception:
            return []

    def _display_results(self, pairs: list[tuple[str, str]]):
        """Display cracked results in clean format."""
        self._print("")
        self._print("  ╔══════════════════════════════════════════════════════╗")
        self._print("  ║           🎉  Hash Successfully Cracked!             ║")
        self._print("  ╠══════════════════════════════════════════════════════╣")
        for h, pw in pairs:
            h_disp = (h[:36] + "…") if len(h) > 38 else h
            self._print(f"  ║  {h_disp}")
            self._print(f"  ║      =  [{pw}]")
        self._print("  ╚══════════════════════════════════════════════════════╝")
        self._print("")

    def _offer_john_fallback(self, target: str, extra: list):
        """Ask the user if they want to try John after hashcat fails."""
        answer = messagebox.askyesno(
            "Hashcat couldn't crack it",
            "Hashcat exhausted all wordlists without a result.\n\n"
            "Would you like to try John the Ripper with a brute-force attack instead?",
        )
        if not answer:
            return
        self._print("")
        self._print("  Switching to John the Ripper — brute force mode...")
        threading.Thread(
            target=self._john_brute_fallback,
            args=(target, extra),
            daemon=True,
        ).start()

    def _john_brute_fallback(self, target: str, extra: list):
        """Run John in incremental (brute force) mode as a last-resort fallback."""
        self.btn_run.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        binary = shutil.which("john") or "john"
        if not shutil.which("john"):
            self._print("  John not found — cannot run fallback.")
            self._reset_buttons()
            return

        self._print("  Engine    John the Ripper  (incremental / brute force)")
        self._print(f"  Target    {target}")
        self._print("")

        cmd = [binary, "--incremental", target] + extra
        self._run_silent(cmd)
        result = self._john_show(binary, target)

        if result:
            self._display_results(result)
        else:
            self._print("  John also could not crack the hash.")
            self._print("  Consider a longer brute force, different hash mode, or custom rules.")

        self._reset_buttons()

    def _stop_engine(self):
        self.stop_requested = True
        if self.active_proc:
            self.active_proc.terminate()
            self._print("  Stop signal sent.")

    def _reset_buttons(self):
        self.btn_run.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self._update_status_bar()

    def _view_pot(self):
        pairs = StorageEngine.parse_pot()
        size  = StorageEngine.get_pot_size_mb()
        self._print("")
        self._print("  ++=====++ [Gold Goblet]  GOLD POT  [Gold Goblet] ++=====++")
        self._print(f"  Size: {size} MB  |  Entries: {len(pairs)}")
        self._print("  ─────────────────────────────────────────────────────────")
        if pairs:
            for h, pw in pairs:
                h_disp = (h[:36] + "…") if len(h) > 38 else h
                self._print(f"  [{h_disp}] = [{pw}]")
        else:
            self._print("  (empty — crack something first)")
        self._print("  ++=======================================================++")
        self._print("")

    def _purge_pot(self):
        if messagebox.askyesno("Purge Gold Pot", "Delete ALL cracked hash entries?"):
            if StorageEngine.purge_pot():
                self._print("  Gold Pot purged.")
                self._update_status_bar()
            else:
                self._print("  Pot file not found.")

    def _copy_last_result(self):
        content = self.log_box.get("1.0", "end").strip()
        if not content:
            return
        self.clipboard_clear()
        self.clipboard_append(content.splitlines()[-1])
        self._print("  Last line copied to clipboard.")

    # ----------------------------------------------------------------
    # FORGE LOGIC
    # ----------------------------------------------------------------
    def _toggle_hmac_ui(self):
        if self.forge_hmac_var.get():
            self.hmac_row.pack(fill="x", padx=10, pady=2)
        else:
            self.hmac_row.pack_forget()

    def _gen_salt(self):
        s = ForgeEngine.generate_salt(16)
        self.forge_salt_entry.delete(0, "end")
        self.forge_salt_entry.insert(0, s)

    def _run_forge(self):
        text = self.forge_input.get("1.0", "end").strip()
        if not text:
            return
        algo  = self.forge_algo.get()
        salt  = self.forge_salt_entry.get().strip()
        try:
            iters = max(1, int(self.forge_iter.get() or 1))
        except ValueError:
            iters = 1

        if self.forge_hmac_var.get():
            key    = self.forge_hmac_key.get().strip()
            result = ForgeEngine.hmac_hash(text, key, algo)
            header = f"HMAC-{algo}  key={key!r}"
        else:
            result = ForgeEngine.hash_text(text, algo, salt, iters)
            header = f"{algo}  salt={salt!r}  iters={iters}"

        self.forge_output.delete("1.0", "end")
        self.forge_output.insert("1.0",
            f"Algorithm : {header}\n"
            f"Input     : {text[:60]}{'...' if len(text) > 60 else ''}\n"
            f"Result    : {result}\n"
        )

    def _copy_forge_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.forge_output.get("1.0", "end").strip())

    def _run_verify(self):
        plain = self.verify_plain.get().strip()
        known = self.verify_hash_entry.get().strip()
        algo  = self.forge_algo.get()
        salt  = self.forge_salt_entry.get().strip()
        if not plain or not known:
            return
        computed = ForgeEngine.hash_text(plain, algo, salt)
        if computed.lower() == known.lower():
            self.verify_result.configure(
                text=f"MATCH  -  {algo} of '{plain}' equals the known hash.",
                text_color=AppConfig.color_accent)
        else:
            self.verify_result.configure(
                text=f"NO MATCH  -  computed: {computed[:40]}...",
                text_color=AppConfig.color_danger)

    # ----------------------------------------------------------------
    # INFO TAB WORKERS
    # ----------------------------------------------------------------
    def _fetch_versions(self):
        # hashcat — real version check
        hc_ver, hc_path = UpdateEngine.get_tool_version("hashcat")
        hc_color = AppConfig.color_term_text if "NOT FOUND" not in hc_ver else AppConfig.color_danger
        self.after(0, lambda v=hc_ver, c=hc_color: self.version_labels["hashcat"].configure(text=v, text_color=c))
        self.after(0, lambda p=hc_path or "not in PATH": self.version_path_labels["hashcat"].configure(text=p))

        # john — version output is unreliable; point to the repo
        john_path = shutil.which("john")
        john_status = john_path if john_path else "NOT FOUND"
        john_note   = f"See {AppConfig.REPO_URL}"
        john_color  = AppConfig.color_term_text if john_path else AppConfig.color_danger
        self.after(0, lambda n=john_note, c=john_color: self.version_labels["john"].configure(text=n, text_color=c))
        self.after(0, lambda p=john_status: self.version_path_labels["john"].configure(text=p))

    def _run_integrity_check(self):
        ok, msg = AppConfig.integrity_check()
        if ok:
            self.after(0, lambda: self.integrity_label.configure(
                text="✅  Verified", text_color=AppConfig.color_accent))
        else:
            self.after(0, lambda: self.integrity_label.configure(
                text="⚠  Mismatch — see warning", text_color=AppConfig.color_danger))
            self.after(0, lambda: messagebox.showwarning("Integrity Warning", msg))

    def _check_updates(self):
        self.after(0, lambda: self.latest_ver_label.configure(
            text="Checking GitHub…", text_color="#aaa"))
        remote = UpdateEngine.check_remote_version()

        if remote == "OFFLINE":
            color = AppConfig.color_warn
            msg   = "No internet connection"
            popup = (False, "No Connection",
                     "Could not reach GitHub.\nCheck your internet connection.")

        elif remote == "NO_RELEASES":
            color = "#888"
            msg   = "No releases published yet"
            popup = (False, "No Releases",
                     f"The repository has no published releases yet.\n"
                     f"You are running version {AppConfig.VERSION}.\n\n"
                     f"Check back at:\n{AppConfig.REPO_URL}")

        elif remote.startswith("Error"):
            color = AppConfig.color_danger
            msg   = remote
            popup = (False, "Update Check Error",
                     f"GitHub returned an error:\n{remote}\n\n"
                     f"Try visiting the repo directly:\n{AppConfig.REPO_URL}")

        elif remote.strip().lstrip("vV") == AppConfig.VERSION.strip().lstrip("vV"):
            color = AppConfig.color_accent
            msg   = f"{remote}  ✅  Up to date"
            popup = (False, "Up to Date",
                     f"You are running the latest release:\n{remote}")

        else:
            color = AppConfig.color_warn
            msg   = f"{remote}  ⬆️  Update available"
            popup = (True, "Update Available",
                     f"A new release is available:  {remote}\n"
                     f"You have:                    {AppConfig.VERSION}\n\n"
                     f"Download from:\n{AppConfig.REPO_URL}/releases")

        self.after(0, lambda: self.latest_ver_label.configure(text=msg, text_color=color))
        self._print(f"  Update check:  {msg}")

        is_warn, title, body = popup
        fn = messagebox.showwarning if is_warn else messagebox.showinfo
        self.after(0, lambda t=title, b=body: fn(t, b))

    # ----------------------------------------------------------------
    # MISC
    # ----------------------------------------------------------------
    def _open_url(self, url: str):
        import webbrowser
        webbrowser.open(url)

    def _update_status_bar(self):
        size    = StorageEngine.get_pot_size_mb()
        entries = len(StorageEngine.parse_pot())
        wls     = len(AppConfig.get_wordlists())
        self.status_bar.configure(
            text=f"  Pot: {size} MB ({entries} entries)  |  Wordlists: {wls}  |  {AppConfig.VERSION}"
        )

    def _print(self, message: str):
        """Write a clean line to the terminal — no prefix."""
        self.log_box.insert("end", f"{message}\n")
        self.log_box.see("end")

    def _log(self, message: str):
        """Internal messages — no prefix."""
        self._print(message)

    def _sunday_check(self):
        if datetime.datetime.today().weekday() == 6:
            self._print("  Sunday routine: checking for updates...")
            threading.Thread(target=self._check_updates, daemon=True).start()


# =================================================================
if __name__ == "__main__":
    app = MintHashMaster()
    app.mainloop()
