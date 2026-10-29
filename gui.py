"""CustomTkinter GUI for the Secure Adaptive Image Steganography Toolkit.

The GUI is intentionally a thin, security-conscious client over the Python
facade in ``main.py``. It keeps cryptography, engine selection, evaluation, and
manifest handling in the audited backend while giving beginners a guided,
visual workflow.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hmac
import logging
from pathlib import Path
import re
import tkinter as tk
from tkinter import filedialog
from typing import Any, Callable, Literal, Mapping, Optional, Sequence

import customtkinter as ctk
from PIL import Image, ImageChops, ImageDraw, ImageEnhance, ImageOps

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except Exception:  # pragma: no cover - optional native dependency
    DND_FILES = None
    TkinterDnD = None  # type: ignore[assignment]

from main import StegoToolkit, classify_resistance_score, configure_logging

logger = logging.getLogger(__name__)

BG = "#121212"
SURFACE = "#1e1e1e"
CARD = "#242424"
CARD_HOVER = "#2b2b2b"
CARD_SOFT = "#191919"
BORDER = "#343434"
BLUE = "#3b8ed0"
BLUE_HOVER = "#2f76ad"
GREEN = "#2eb872"
CYAN = "#5fd4ff"
YELLOW = "#d6a931"
RED = "#d9534f"
TEXT = "#f4f7fb"
MUTED = "#9ba7b4"
INPUT = "#151515"
WHITE = "#ffffff"

ENCRYPTED_ENVELOPE_OVERHEAD_BYTES = 74
PREVIEW_SIZE = (420, 300)
CARD_PAD = 20


class DragDropCTk(ctk.CTk):
    """CTk root that can load tkdnd when the optional package is available."""

    def enable_native_dnd(self) -> bool:
        """Load tkdnd into a CustomTkinter root if the runtime supports it."""

        if TkinterDnD is None:
            return False
        try:
            self.TkdndVersion = TkinterDnD._require(self)  # type: ignore[attr-defined]
        except Exception as exc:  # pragma: no cover - platform specific
            logger.info("Native drag and drop unavailable: %s", exc)
            return False
        return True


class ToastManager:
    """Non-blocking toast notifications for success, warning, and error states."""

    def __init__(self, root: ctk.CTk) -> None:
        self.root = root
        self._active: list[ctk.CTkFrame] = []

    def show(
        self,
        message: str,
        *,
        kind: Literal["success", "info", "warning", "error"] = "info",
        duration_ms: int = 3600,
    ) -> None:
        color = {
            "success": GREEN,
            "info": BLUE,
            "warning": YELLOW,
            "error": RED,
        }[kind]
        toast = ctk.CTkFrame(
            self.root,
            fg_color=SURFACE,
            border_color=color,
            border_width=1,
            corner_radius=10,
        )
        label = ctk.CTkLabel(
            toast,
            text=message,
            text_color=TEXT,
            font=ctk.CTkFont(size=13, weight="bold"),
            justify="left",
            wraplength=360,
        )
        label.pack(padx=16, pady=12)
        offset = 24 + (len(self._active) * 64)
        toast.place(relx=1.0, x=-24, y=offset, anchor="ne")
        toast.lift()
        self._active.append(toast)
        self.root.after(duration_ms, lambda: self._dismiss(toast))

    def _dismiss(self, toast: ctk.CTkFrame) -> None:
        if toast in self._active:
            self._active.remove(toast)
        toast.destroy()
        for index, item in enumerate(self._active):
            item.place_configure(y=24 + (index * 64))


class CardFrame(ctk.CTkFrame):
    """Consistent card container used throughout the application."""

    def __init__(self, master: ctk.CTkBaseClass, title: str | None = None, **kwargs: Any) -> None:
        super().__init__(
            master,
            fg_color=CARD,
            border_color=BORDER,
            border_width=1,
            corner_radius=15,
            **kwargs,
        )
        self.grid_columnconfigure(0, weight=1)
        if title:
            ctk.CTkLabel(
                self,
                text=title,
                text_color=TEXT,
                font=ctk.CTkFont(size=16, weight="bold"),
            ).grid(row=0, column=0, sticky="w", padx=CARD_PAD, pady=(18, 10))


class IconFactory:
    """Small PIL icon factory to avoid external asset dependencies."""

    @staticmethod
    def nav(kind: str, color: str) -> ctk.CTkImage:
        image = Image.new("RGBA", (28, 28), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        if kind == "dashboard":
            for x, y in ((4, 4), (15, 4), (4, 15), (15, 15)):
                draw.rounded_rectangle((x, y, x + 8, y + 8), radius=2, outline=color, width=2)
        elif kind == "embed":
            draw.rounded_rectangle((5, 5, 23, 23), radius=4, outline=color, width=2)
            draw.line((14, 9, 14, 19), fill=color, width=2)
            draw.line((9, 14, 14, 9, 19, 14), fill=color, width=2)
        elif kind == "extract":
            draw.rounded_rectangle((5, 5, 23, 23), radius=4, outline=color, width=2)
            draw.line((14, 9, 14, 19), fill=color, width=2)
            draw.line((9, 14, 14, 19, 19, 14), fill=color, width=2)
        elif kind == "evaluate":
            draw.arc((4, 4, 24, 24), start=205, end=335, fill=color, width=3)
            draw.line((14, 14, 20, 9), fill=color, width=2)
            draw.ellipse((12, 12, 16, 16), fill=color)
        else:
            draw.ellipse((5, 5, 23, 23), outline=color, width=2)
        return ctk.CTkImage(light_image=image, dark_image=image, size=(22, 22))

    @staticmethod
    def shield(color: str, glow: bool = False) -> ctk.CTkImage:
        image = Image.new("RGBA", (42, 42), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        if glow:
            draw.ellipse((2, 2, 40, 40), fill=_hex_rgba(color, 42))
        points = [(21, 5), (34, 10), (32, 24), (21, 36), (10, 24), (8, 10)]
        draw.polygon(points, fill=_hex_rgba(color, 62), outline=color)
        draw.line((15, 21, 19, 25, 28, 15), fill=WHITE, width=3)
        return ctk.CTkImage(light_image=image, dark_image=image, size=(34, 34))

    @staticmethod
    def upload(color: str) -> ctk.CTkImage:
        image = Image.new("RGBA", (62, 62), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((12, 35, 50, 49), radius=5, outline=color, width=3)
        draw.line((31, 13, 31, 37), fill=color, width=4)
        draw.line((20, 24, 31, 13, 42, 24), fill=color, width=4)
        return ctk.CTkImage(light_image=image, dark_image=image, size=(46, 46))

    @staticmethod
    def check(color: str = GREEN) -> ctk.CTkImage:
        image = Image.new("RGBA", (24, 24), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.ellipse((2, 2, 22, 22), fill=_hex_rgba(color, 45), outline=color, width=2)
        draw.line((7, 12, 11, 16, 18, 8), fill=WHITE, width=3)
        return ctk.CTkImage(light_image=image, dark_image=image, size=(20, 20))


class SecurityHeader(ctk.CTkFrame):
    """Persistent HSALA status header with visible cryptographic posture."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, fg_color=SURFACE, corner_radius=0)
        self.grid_columnconfigure(1, weight=1)
        self._shield = ctk.CTkLabel(self, text="", image=IconFactory.shield(YELLOW, glow=False))
        self._shield.grid(row=0, column=0, padx=(22, 12), pady=14)
        self._title = ctk.CTkLabel(
            self,
            text="AES-GCM 256-bit | Argon2id Active",
            text_color=TEXT,
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        self._title.grid(row=0, column=1, sticky="w")
        self._badge = ctk.CTkLabel(
            self,
            text="Password: Not Set",
            fg_color="#3a3020",
            text_color=TEXT,
            corner_radius=16,
            padx=14,
            pady=7,
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self._badge.grid(row=0, column=2, padx=22, sticky="e")

    def update_password(self, password: str) -> None:
        label, color, glow = _password_strength(password)
        self._shield.configure(image=IconFactory.shield(color, glow=glow))
        self._badge.configure(text=f"Password: {label}", fg_color=color)


class SecurityStatusBar(ctk.CTkFrame):
    """Sidebar security health indicator using perceptible status colors."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(
            master,
            fg_color=CARD_SOFT,
            border_color=BORDER,
            border_width=1,
            corner_radius=15,
        )
        self.grid_columnconfigure(1, weight=1)
        self._shield = ctk.CTkLabel(self, text="", image=IconFactory.shield(RED, glow=False))
        self._shield.grid(row=0, column=0, rowspan=2, padx=(14, 10), pady=14)
        self._title = ctk.CTkLabel(
            self,
            text="Security Health",
            text_color=TEXT,
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
        )
        self._title.grid(row=0, column=1, padx=(0, 14), pady=(14, 1), sticky="ew")
        self._status = ctk.CTkLabel(
            self,
            text="No password",
            text_color=MUTED,
            font=ctk.CTkFont(size=11),
            anchor="w",
            wraplength=145,
        )
        self._status.grid(row=1, column=1, padx=(0, 14), pady=(0, 14), sticky="ew")

    def update_password(self, password: str) -> None:
        label, color, glow = _password_strength(password)
        if label == "Strong":
            status = "AES-GCM 256-bit + Argon2id active"
        elif password:
            status = "Password set; strengthen for demo-grade posture"
        else:
            status = "Encryption cannot start"
        self._shield.configure(image=IconFactory.shield(color, glow=glow))
        self._status.configure(text=status, text_color=color)


class SidebarFrame(ctk.CTkFrame):
    """Left navigation rail with icon-driven view switching."""

    def __init__(self, master: ctk.CTkBaseClass, on_select: Callable[[str], None]) -> None:
        super().__init__(master, fg_color=SURFACE, corner_radius=0)
        self._on_select = on_select
        self._buttons: dict[str, ctk.CTkButton] = {}
        self.grid_rowconfigure(6, weight=1)
        ctk.CTkLabel(
            self,
            text="STEGKIT",
            text_color=TEXT,
            font=ctk.CTkFont(size=22, weight="bold"),
        ).grid(row=0, column=0, padx=18, pady=(24, 2), sticky="w")
        ctk.CTkLabel(
            self,
            text="Adaptive Security Console",
            text_color=MUTED,
            font=ctk.CTkFont(size=12),
        ).grid(row=1, column=0, padx=18, pady=(0, 22), sticky="w")

        items = [
            ("dashboard", "Dashboard", "dashboard"),
            ("embed", "Embed Data", "embed"),
            ("extract", "Extract Data", "extract"),
            ("evaluate", "Evaluation Harness", "evaluate"),
        ]
        for index, (key, label, icon_kind) in enumerate(items, start=2):
            self._buttons[key] = self._make_nav_button(key, label, icon_kind, row=index)
        self.status_bar = SecurityStatusBar(self)
        self.status_bar.grid(row=7, column=0, padx=14, pady=(10, 18), sticky="ew")
        self.set_active("dashboard")

    def set_active(self, key: str) -> None:
        for item_key, button in self._buttons.items():
            active = item_key == key
            button.configure(
                fg_color=BLUE if active else SURFACE,
                text_color=WHITE if active else MUTED,
                image=IconFactory.nav(item_key if item_key != "evaluate" else "evaluate", WHITE if active else MUTED),
            )

    def _make_nav_button(self, key: str, label: str, icon_kind: str, row: int) -> ctk.CTkButton:
        button = ctk.CTkButton(
            self,
            text=label,
            image=IconFactory.nav(icon_kind, MUTED),
            anchor="w",
            fg_color=SURFACE,
            hover_color=CARD_HOVER,
            text_color=MUTED,
            corner_radius=10,
            height=44,
            command=lambda: self._on_select(key),
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        button.grid(row=row, column=0, padx=14, pady=5, sticky="ew")
        return button

    def update_security(self, password: str) -> None:
        self.status_bar.update_password(password)


class CapacityGauge(ctk.CTkFrame):
    """Circular gauge representing estimated payload usage."""

    def __init__(self, master: ctk.CTkBaseClass, size: int = 168) -> None:
        super().__init__(master, fg_color=CARD, corner_radius=0)
        self.size = size
        self._value = 0.0
        self._label = "0%"
        self._canvas = tk.Canvas(
            self,
            width=size,
            height=size,
            bg=CARD,
            highlightthickness=0,
            bd=0,
        )
        self._canvas.pack(expand=True, fill="both")
        self._draw_gauge()

    def set(self, value: float, label: str | None = None) -> None:
        self._value = max(0.0, min(1.0, value))
        self._label = label or f"{self._value * 100.0:.1f}%"
        self._draw_gauge()

    def _draw_gauge(self) -> None:
        self._canvas.delete("all")
        pad = 16
        bbox = (pad, pad, self.size - pad, self.size - pad)
        percent = self._value * 100.0
        color = GREEN if percent < 70 else YELLOW if percent < 92 else RED
        self._canvas.create_oval(*bbox, outline="#343434", width=14)
        self._canvas.create_arc(
            *bbox,
            start=90,
            extent=-360 * self._value,
            style="arc",
            outline=color,
            width=14,
        )
        self._canvas.create_text(
            self.size / 2,
            self.size / 2 - 6,
            text=self._label,
            fill=TEXT,
            font=("Segoe UI", 18, "bold"),
        )
        self._canvas.create_text(
            self.size / 2,
            self.size / 2 + 22,
            text="Capacity",
            fill=MUTED,
            font=("Segoe UI", 10),
        )


class LinearMetricGauge(ctk.CTkFrame):
    """Glanceable evaluation metric rendered as a colored progress gauge."""

    def __init__(self, master: ctk.CTkBaseClass, title: str, suffix: str = "%") -> None:
        super().__init__(master, fg_color=CARD, corner_radius=0)
        self.suffix = suffix
        self.grid_columnconfigure(0, weight=1)
        self._title = ctk.CTkLabel(
            self,
            text=title,
            text_color=MUTED,
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w",
        )
        self._title.grid(row=0, column=0, sticky="w")
        self._value = ctk.CTkLabel(
            self,
            text="--",
            text_color=TEXT,
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="e",
        )
        self._value.grid(row=0, column=1, padx=(12, 0), sticky="e")
        self._bar = ctk.CTkProgressBar(
            self,
            height=12,
            fg_color="#343434",
            progress_color=RED,
            mode="determinate",
        )
        self._bar.grid(row=1, column=0, columnspan=2, pady=(8, 0), sticky="ew")
        self._bar.set(0)

    def set_metric(self, value: float, max_value: float = 100.0) -> None:
        fraction = max(0.0, min(1.0, value / max_value if max_value else 0.0))
        color = GREEN if fraction >= 0.75 else YELLOW if fraction >= 0.5 else RED
        self._bar.configure(progress_color=color)
        self._bar.set(fraction)
        display = f"{value:.2f}{self.suffix}" if self.suffix else f"{value:.4f}"
        self._value.configure(text=display, text_color=color)


class PipelineStageStrip(CardFrame):
    """Compact W1-W8 research pipeline strip from the FYP methodology."""

    _STAGES: tuple[tuple[str, str], ...] = (
        ("W1", "Carrier Load"),
        ("W2", "Payload Security"),
        ("W3", "Sizing Log"),
        ("W4", "Embed"),
        ("W5", "Transform"),
        ("W6", "Verify"),
        ("W7", "Steganalysis"),
        ("W8", "Report"),
    )

    def __init__(self, master: ctk.CTkBaseClass, title: str = "Research Pipeline") -> None:
        super().__init__(master, title=title)
        self._labels: dict[str, ctk.CTkLabel] = {}
        row = ctk.CTkFrame(self, fg_color=CARD)
        row.grid(row=1, column=0, padx=CARD_PAD, pady=(0, CARD_PAD), sticky="ew")
        for index in range(len(self._STAGES)):
            row.grid_columnconfigure(index, weight=1, uniform="pipeline")
        for index, (stage_id, label) in enumerate(self._STAGES):
            pill = ctk.CTkLabel(
                row,
                text=f"{stage_id}\n{label}",
                fg_color="#303030",
                text_color=MUTED,
                corner_radius=12,
                padx=10,
                pady=8,
                font=ctk.CTkFont(size=11, weight="bold"),
                justify="center",
            )
            pill.grid(row=0, column=index, padx=4, sticky="ew")
            self._labels[stage_id] = pill

    def set_progress(self, completed: Sequence[str], active: str | None = None) -> None:
        completed_set = set(completed)
        for stage_id, _label in self._STAGES:
            pill = self._labels[stage_id]
            if stage_id == active:
                pill.configure(fg_color=BLUE, text_color=WHITE)
            elif stage_id in completed_set:
                pill.configure(fg_color=GREEN, text_color=WHITE)
            else:
                pill.configure(fg_color="#303030", text_color=MUTED)


class CryptoPipelineCard(CardFrame):
    """Visible security pipeline proving Argon2id and AES-GCM are mandatory."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, title="Crypto Assurance Pipeline")
        self._labels: list[ctk.CTkLabel] = []
        stages = ["Password", "Argon2id KDF", "AES-GCM 256-bit", "Authenticated Stego"]
        row = ctk.CTkFrame(self, fg_color=CARD)
        row.grid(row=1, column=0, padx=CARD_PAD, pady=(0, 10), sticky="ew")
        for index in range(len(stages)):
            row.grid_columnconfigure(index, weight=1, uniform="crypto")
        for index, stage in enumerate(stages):
            label = ctk.CTkLabel(
                row,
                text=stage,
                fg_color="#303030",
                text_color=MUTED,
                corner_radius=12,
                padx=10,
                pady=10,
                font=ctk.CTkFont(size=11, weight="bold"),
            )
            label.grid(row=0, column=index, padx=4, sticky="ew")
            self._labels.append(label)
        self._caption = ctk.CTkLabel(
            self,
            text="Enter a strong password to activate the full authenticated encryption path.",
            text_color=MUTED,
            wraplength=310,
            justify="left",
        )
        self._caption.grid(row=2, column=0, padx=CARD_PAD, pady=(0, CARD_PAD), sticky="w")

    def update_password(self, password: str, embedded: bool = False) -> None:
        label, color, glow = _password_strength(password)
        active_count = 0 if not password else 3
        if embedded:
            active_count = 4
        for index, item in enumerate(self._labels):
            if index < active_count:
                item.configure(fg_color=GREEN if glow or embedded else YELLOW, text_color=WHITE)
            else:
                item.configure(fg_color="#303030", text_color=MUTED)
        if embedded:
            self._caption.configure(text="Payload was encrypted, embedded, and trial-extracted successfully.", text_color=GREEN)
        elif password:
            self._caption.configure(text=f"Password posture: {label}. Argon2id + AES-GCM will run before any embedding.", text_color=color)
        else:
            self._caption.configure(text="No password entered. Embedding is blocked until encryption can run.", text_color=RED)


class ReproducibilityCard(CardFrame):
    """Run metadata panel for auditability and academic repeatability."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, title="Reproducibility & Audit")
        self._body = ctk.CTkTextbox(
            self,
            height=154,
            fg_color=INPUT,
            text_color=TEXT,
            border_color=BORDER,
            border_width=1,
            corner_radius=10,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=11),
        )
        self._body.grid(row=1, column=0, sticky="nsew", padx=CARD_PAD, pady=(0, CARD_PAD))
        self.set_text("[AUDIT]: No run artifact yet.\nRun embedding or evaluation to populate manifest/report metadata.")

    def set_text(self, text: str) -> None:
        self._body.configure(state="normal")
        self._body.delete("1.0", "end")
        self._body.insert("1.0", text)
        self._body.configure(state="disabled")

    def update_embedding(self, result: Mapping[str, Any]) -> None:
        config = dict(result.get("selected_config", {}))
        manifest = Path(str(result.get("manifest_path", "")))
        audit = [
            "[AUDIT]: Embedding run captured.",
            f"Carrier: {Path(str(result.get('cover_path', ''))).name}",
            f"Stego: {Path(str(result.get('stego_path', ''))).name}",
            f"Engine: {config.get('engine_name', 'unknown')}",
            f"Payload bits: {int(result.get('embedded_payload_bits', 0)):,}",
            f"Manifest: {manifest.name}",
            "Crypto: Argon2id KDF + AES-GCM AEAD",
        ]
        self.set_text("\n".join(audit))

    def update_evaluation(self, report: Mapping[str, Any], report_path: Path) -> None:
        detectability = dict(report.get("detectability", {}))
        resistance = dict(report.get("resistance_score", {}))
        audit = [
            "[AUDIT]: Evaluation report captured.",
            f"Carrier format: {report.get('carrier_format', 'unknown')}",
            f"ROC AUC: {float(detectability.get('roc_auc', 0.0)):.6f}",
            f"Resistance: {float(resistance.get('final_score', 0.0)):.2f}/100",
            f"Markdown: {report_path.resolve()}",
            "Protocol: PSNR + SSIM + ROC/AUC + transform robustness",
        ]
        self.set_text("\n".join(audit))


class MetricTile(ctk.CTkFrame):
    """Small command-center tile with a label, value, and colored state rail."""

    def __init__(self, master: ctk.CTkBaseClass, label: str, value: str, color: str = BLUE) -> None:
        super().__init__(
            master,
            fg_color=CARD_SOFT,
            border_color=BORDER,
            border_width=1,
            corner_radius=14,
        )
        self.grid_columnconfigure(1, weight=1)
        self._rail = ctk.CTkFrame(self, fg_color=color, width=4, corner_radius=3)
        self._rail.grid(row=0, column=0, rowspan=2, padx=(10, 9), pady=11, sticky="ns")
        self._label = ctk.CTkLabel(
            self,
            text=label,
            text_color=MUTED,
            font=ctk.CTkFont(size=11, weight="bold"),
            anchor="w",
        )
        self._label.grid(row=0, column=1, padx=(0, 12), pady=(10, 0), sticky="ew")
        self._value = ctk.CTkLabel(
            self,
            text=value,
            text_color=TEXT,
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        )
        self._value.grid(row=1, column=1, padx=(0, 12), pady=(0, 10), sticky="ew")

    def update(self, value: str, color: str = BLUE) -> None:
        self._value.configure(text=value, text_color=color)
        self._rail.configure(fg_color=color)


class CommandCenterCard(CardFrame):
    """High-level operational overview for the live demo dashboard."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, title="Mission Control")
        self.grid_columnconfigure(0, weight=1)
        self._subtitle = ctk.CTkLabel(
            self,
            text="Adaptive steganography, cryptographic assurance, and reproducible evaluation in one workflow.",
            text_color=MUTED,
            font=ctk.CTkFont(size=13),
            anchor="w",
            wraplength=760,
        )
        self._subtitle.grid(row=1, column=0, padx=CARD_PAD, pady=(0, 14), sticky="ew")
        tiles = ctk.CTkFrame(self, fg_color=CARD)
        tiles.grid(row=2, column=0, padx=CARD_PAD, pady=(0, CARD_PAD), sticky="ew")
        tiles.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="tiles")
        self.carrier_tile = MetricTile(tiles, "Carrier", "Awaiting image", BLUE)
        self.carrier_tile.grid(row=0, column=0, padx=(0, 8), sticky="ew")
        self.engine_tile = MetricTile(tiles, "Adaptive Engine", "Policy idle", CYAN)
        self.engine_tile.grid(row=0, column=1, padx=8, sticky="ew")
        self.crypto_tile = MetricTile(tiles, "Crypto State", "Password required", RED)
        self.crypto_tile.grid(row=0, column=2, padx=8, sticky="ew")
        self.resistance_tile = MetricTile(tiles, "Resistance", "Not evaluated", YELLOW)
        self.resistance_tile.grid(row=0, column=3, padx=(8, 0), sticky="ew")

    def update_carrier(self, analysis: Mapping[str, Any]) -> None:
        fmt = str(analysis.get("format", "unknown"))
        width = analysis.get("width", "-")
        height = analysis.get("height", "-")
        self.carrier_tile.update(f"{fmt} | {width}x{height}", GREEN)

    def update_engine(self, config: Mapping[str, Any] | None) -> None:
        if not config:
            self.engine_tile.update("Policy idle", CYAN)
            return
        engine = str(config.get("engine_name", "Unknown"))
        self.engine_tile.update(engine, GREEN if engine != "Policy Blocked" else RED)

    def update_crypto(self, password: str, embedded: bool = False) -> None:
        label, color, _glow = _password_strength(password)
        if embedded:
            self.crypto_tile.update("AES-GCM verified", GREEN)
        elif password:
            self.crypto_tile.update(f"Argon2id ready | {label}", color)
        else:
            self.crypto_tile.update("Password required", RED)

    def update_resistance(self, score: float | None) -> None:
        if score is None:
            self.resistance_tile.update("Not evaluated", YELLOW)
            return
        status = classify_resistance_score(score)
        self.resistance_tile.update(f"{score:.2f}/100 | {status['label']}", status["gui_color"])


class SignalFlowCard(CardFrame):
    """Canvas-based system flow map for a premium research-workstation feel."""

    _NODES: tuple[tuple[str, str], ...] = (
        ("cover", "Cover"),
        ("crypto", "Crypto"),
        ("selector", "Selector"),
        ("embed", "Embed"),
        ("verify", "Verify"),
        ("evaluate", "Evaluate"),
    )

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, title="Live Signal Flow")
        self._completed: set[str] = set()
        self._active: str | None = None
        self._canvas = tk.Canvas(self, height=126, bg=CARD, highlightthickness=0, bd=0)
        self._canvas.grid(row=1, column=0, padx=CARD_PAD, pady=(0, CARD_PAD), sticky="nsew")
        self._canvas.bind("<Configure>", lambda _event: self._draw_flow())
        self._draw_flow()

    def set_state(self, completed: Sequence[str], active: str | None = None) -> None:
        self._completed = set(completed)
        self._active = active
        self._draw_flow()

    def _draw_flow(self) -> None:
        self._canvas.delete("all")
        width = max(520, self._canvas.winfo_width())
        height = 126
        left = 38
        right = width - 38
        y = height // 2
        gap = (right - left) / (len(self._NODES) - 1)
        coords: dict[str, tuple[float, float]] = {}
        for index, (node_id, _label) in enumerate(self._NODES):
            coords[node_id] = (left + gap * index, y)
        for first, second in zip(self._NODES, self._NODES[1:]):
            x1, y1 = coords[first[0]]
            x2, y2 = coords[second[0]]
            done = first[0] in self._completed and second[0] in self._completed
            color = GREEN if done else "#3a3a3a"
            self._canvas.create_line(x1 + 24, y1, x2 - 24, y2, fill=color, width=3)
        for node_id, label in self._NODES:
            x, y_pos = coords[node_id]
            if node_id == self._active:
                fill = BLUE
                text_color = WHITE
            elif node_id in self._completed:
                fill = GREEN
                text_color = WHITE
            else:
                fill = "#303030"
                text_color = MUTED
            self._canvas.create_oval(x - 22, y_pos - 22, x + 22, y_pos + 22, fill=fill, outline=fill)
            self._canvas.create_text(x, y_pos, text=str(self._NODES.index((node_id, label)) + 1), fill=text_color, font=("Segoe UI", 11, "bold"))
            self._canvas.create_text(x, y_pos + 38, text=label, fill=text_color, font=("Segoe UI", 9, "bold"))


class DropZoneFrame(CardFrame):
    """Large dashed carrier input area with hover and optional OS drop events."""

    def __init__(self, master: ctk.CTkBaseClass, on_pick: Callable[[], None]) -> None:
        super().__init__(master)
        self._on_pick = on_pick
        self.grid_columnconfigure(0, weight=1)
        self._canvas = tk.Canvas(self, height=190, bg=CARD, highlightthickness=0, bd=0)
        self._canvas.grid(row=0, column=0, sticky="nsew", padx=CARD_PAD, pady=(CARD_PAD, 10))
        self._accent = BLUE
        self._draw_zone()
        self._canvas.bind("<Button-1>", lambda _event: self._on_pick())
        self._canvas.bind("<Enter>", lambda _event: self.set_hover(True))
        self._canvas.bind("<Leave>", lambda _event: self.set_hover(False))
        self._canvas.bind("<Configure>", lambda _event: self._draw_zone())
        self._select_button = ctk.CTkButton(
            self,
            text="Select File",
            image=IconFactory.upload(BLUE),
            compound="left",
            fg_color=BLUE,
            hover_color=BLUE_HOVER,
            height=52,
            command=self._on_pick,
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self._select_button.grid(row=1, column=0, padx=CARD_PAD, pady=(0, CARD_PAD), sticky="")

    def set_hover(self, active: bool) -> None:
        self._accent = GREEN if active else BLUE
        self._draw_zone()

    def _draw_zone(self) -> None:
        self._canvas.delete("all")
        width = max(420, self._canvas.winfo_width())
        height = 190
        self._canvas.configure(bg=CARD)
        self._canvas.create_rectangle(
            12,
            12,
            width - 12,
            height - 12,
            outline=self._accent,
            width=2,
            dash=(10, 7),
        )
        self._canvas.create_text(
            width / 2,
            66,
            text="Upload Carrier Image",
            fill=TEXT,
            font=("Segoe UI", 18, "bold"),
        )
        self._canvas.create_text(
            width / 2,
            101,
            text="Drop a PNG or JPEG here, or use Select File",
            fill=MUTED,
            font=("Segoe UI", 12),
        )
        self._canvas.create_text(width / 2, 136, text="PNG spatial LSB | JPEG DCT domain", fill=self._accent, font=("Segoe UI", 11, "bold"))


class SelectionLogicCard(CardFrame):
    """Explainable selector output rendered as a compact policy card."""

    def __init__(self, master: ctk.CTkBaseClass, title: str = "Decision Logic") -> None:
        super().__init__(master, title=title)
        self._badge = ctk.CTkLabel(
            self,
            text="Awaiting Carrier",
            image=IconFactory.check(BLUE),
            compound="left",
            fg_color="#203040",
            text_color=TEXT,
            corner_radius=18,
            padx=12,
            pady=7,
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self._badge.grid(row=1, column=0, padx=18, pady=(4, 10), sticky="w")
        self._body = ctk.CTkTextbox(
            self,
            height=148,
            fg_color=INPUT,
            text_color=TEXT,
            border_color=BORDER,
            border_width=1,
            corner_radius=10,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self._body.grid(row=2, column=0, sticky="nsew", padx=CARD_PAD, pady=(0, CARD_PAD))
        self._body.insert("1.0", "[POLICY]: Awaiting carrier analysis.")
        self._body.configure(state="disabled")

    def update_trace(self, config: Mapping[str, Any] | None, trace: Sequence[str]) -> None:
        if not config:
            self._badge.configure(text="Awaiting Carrier", fg_color="#203040", image=IconFactory.check(BLUE))
            text = "[POLICY]: Awaiting carrier analysis."
        else:
            badge = _justification_badge(config)
            self._badge.configure(text=badge, fg_color=GREEN, image=IconFactory.check(GREEN))
            text = _format_policy_audit_log(config, trace)
        self._body.configure(state="normal")
        self._body.delete("1.0", "end")
        self._body.insert("1.0", text)
        self._body.configure(state="disabled")


class IntegrityStatus(ctk.CTkFrame):
    """Embedding verification micro-interaction for lossless payload recovery."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(
            master,
            fg_color=CARD_SOFT,
            border_color=BORDER,
            border_width=1,
            corner_radius=15,
        )
        self.grid_columnconfigure(1, weight=1)
        self._icon = ctk.CTkLabel(self, text="", image=IconFactory.shield(MUTED, glow=False))
        self._icon.grid(row=0, column=0, padx=(14, 10), pady=12)
        self._label = ctk.CTkLabel(
            self,
            text="Integrity check idle",
            text_color=MUTED,
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
        )
        self._label.grid(row=0, column=1, padx=(0, 14), pady=12, sticky="ew")
        self._spinner = ctk.CTkProgressBar(
            self,
            height=8,
            fg_color="#343434",
            progress_color=BLUE,
            mode="indeterminate",
        )
        self._spinner.grid(row=1, column=0, columnspan=2, padx=14, pady=(0, 12), sticky="ew")
        self._spinner.set(0)

    def set_idle(self) -> None:
        self._spinner.stop()
        self._spinner.set(0)
        self._spinner.configure(progress_color=BLUE)
        self._icon.configure(image=IconFactory.shield(MUTED, glow=False))
        self._label.configure(text="Integrity check idle", text_color=MUTED)

    def set_verifying(self, message: str = "Verifying embedded payload") -> None:
        self._spinner.configure(progress_color=BLUE)
        self._spinner.start()
        self._icon.configure(image=IconFactory.shield(BLUE, glow=False))
        self._label.configure(text=message, text_color=BLUE)

    def set_verified(self) -> None:
        self._spinner.stop()
        self._spinner.set(1)
        self._spinner.configure(progress_color=GREEN)
        self._icon.configure(image=IconFactory.check(GREEN))
        self._label.configure(text="Data Verified", text_color=GREEN)

    def set_failed(self, message: str = "Integrity check failed") -> None:
        self._spinner.stop()
        self._spinner.set(1)
        self._spinner.configure(progress_color=RED)
        self._icon.configure(image=IconFactory.shield(RED, glow=False))
        self._label.configure(text=message, text_color=RED)


class ImageComparisonFrame(CardFrame):
    """Cover, stego, and difference-map viewer."""

    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, title="Cover vs. Stego Viewer")
        self.grid_columnconfigure((0, 1), weight=1, uniform="preview")
        self.cover_path: Path | None = None
        self.stego_path: Path | None = None
        self._diff_active = False
        self._cover_label = self._make_preview("Cover Image", 0)
        self._stego_label = self._make_preview("Stego Image", 1)
        self._toggle = ctk.CTkButton(
            self,
            text="Show Difference Map",
            fg_color=BLUE,
            hover_color=BLUE_HOVER,
            command=self.toggle_difference,
            height=36,
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self._toggle.grid(row=3, column=0, columnspan=2, padx=CARD_PAD, pady=(0, CARD_PAD), sticky="ew")

    def set_cover(self, path: Path | None) -> None:
        self.cover_path = path
        self._diff_active = False
        self._render()

    def set_stego(self, path: Path | None) -> None:
        self.stego_path = path
        self._diff_active = False
        self._render()

    def toggle_difference(self) -> None:
        if not self.cover_path or not self.stego_path:
            return
        self._diff_active = not self._diff_active
        self._render()

    def _make_preview(self, title: str, column: int) -> ctk.CTkLabel:
        ctk.CTkLabel(self, text=title, text_color=MUTED, font=ctk.CTkFont(size=12, weight="bold")).grid(
            row=1,
            column=column,
            padx=CARD_PAD,
            pady=(0, 6),
            sticky="w",
        )
        label = ctk.CTkLabel(
            self,
            text="No image loaded",
            text_color=MUTED,
            fg_color=INPUT,
            corner_radius=10,
            height=310,
        )
        label.grid(row=2, column=column, padx=CARD_PAD, pady=(0, 14), sticky="nsew")
        return label

    def _render(self) -> None:
        if self.cover_path:
            self._cover_label.configure(text="", image=_load_ctk_preview(self.cover_path, PREVIEW_SIZE))
        else:
            self._cover_label.configure(text="No image loaded", image=None)
        if self._diff_active and self.cover_path and self.stego_path:
            image = _difference_map(self.cover_path, self.stego_path)
            self._stego_label.configure(text="", image=_image_to_ctk_preview(image, PREVIEW_SIZE))
            self._toggle.configure(text="Show Stego Image")
        elif self.stego_path:
            self._stego_label.configure(text="", image=_load_ctk_preview(self.stego_path, PREVIEW_SIZE))
            self._toggle.configure(text="Show Difference Map")
        else:
            self._stego_label.configure(text="No stego image loaded", image=None)
            self._toggle.configure(text="Show Difference Map")


class DashboardFrame(ctk.CTkFrame):
    """Main intelligence dashboard with carrier, capacity, and selector XUI."""

    def __init__(self, master: ctk.CTkBaseClass, app: "StegoToolkitApp") -> None:
        super().__init__(master, fg_color=BG, corner_radius=0)
        self.app = app
        self.grid_columnconfigure((0, 1, 2), weight=1, uniform="dash")
        self.grid_rowconfigure(3, weight=1)

        self.command_center = CommandCenterCard(self)
        self.command_center.grid(row=0, column=0, columnspan=2, padx=(CARD_PAD, 10), pady=(CARD_PAD, 10), sticky="nsew")
        self.signal_flow = SignalFlowCard(self)
        self.signal_flow.grid(row=0, column=2, padx=(10, CARD_PAD), pady=(CARD_PAD, 10), sticky="nsew")

        self.pipeline = PipelineStageStrip(self, title="W1-W8 Research Execution Pipeline")
        self.pipeline.grid(row=1, column=0, columnspan=3, padx=CARD_PAD, pady=(0, 10), sticky="ew")
        self.pipeline.set_progress([], active="W1")
        self.signal_flow.set_state([], active="cover")

        self.carrier_card = CardFrame(self, title="Carrier Analysis")
        self.carrier_card.grid(row=2, column=0, padx=(CARD_PAD, 10), pady=(10, 12), sticky="nsew")
        self.carrier_text = ctk.CTkLabel(
            self.carrier_card,
            text="No carrier selected.",
            text_color=MUTED,
            justify="left",
            anchor="nw",
            font=ctk.CTkFont(size=13),
        )
        self.carrier_text.grid(row=1, column=0, padx=CARD_PAD, pady=(2, CARD_PAD), sticky="nsew")

        self.capacity_card = CardFrame(self, title="Capacity Gauge")
        self.capacity_card.grid(row=2, column=1, padx=10, pady=(10, 12), sticky="nsew")
        self.capacity_gauge = CapacityGauge(self.capacity_card)
        self.capacity_gauge.grid(row=1, column=0, padx=CARD_PAD, pady=(0, 8))
        self.capacity_caption = ctk.CTkLabel(self.capacity_card, text="Type payload data to estimate usage.", text_color=MUTED)
        self.capacity_caption.grid(row=2, column=0, padx=CARD_PAD, pady=(0, CARD_PAD))

        self.resistance_card = CardFrame(self, title="Resistance Status")
        self.resistance_card.grid(row=2, column=2, padx=(10, CARD_PAD), pady=(10, 12), sticky="nsew")
        self.resistance_badge = ctk.CTkLabel(
            self.resistance_card,
            text="Not Evaluated",
            fg_color="#303030",
            text_color=TEXT,
            corner_radius=18,
            padx=14,
            pady=8,
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self.resistance_badge.grid(row=1, column=0, padx=CARD_PAD, pady=(4, 10), sticky="w")
        self.resistance_text = ctk.CTkLabel(
            self.resistance_card,
            text="Run the evaluation harness after embedding to compute PSNR, SSIM, ROC/AUC, and the unified Resistance Score.",
            text_color=MUTED,
            justify="left",
            wraplength=280,
        )
        self.resistance_text.grid(row=2, column=0, padx=CARD_PAD, pady=(0, CARD_PAD), sticky="nw")

        side_stack = ctk.CTkFrame(self, fg_color=BG)
        side_stack.grid(row=3, column=0, padx=(CARD_PAD, 10), pady=(0, CARD_PAD), sticky="nsew")
        side_stack.grid_columnconfigure(0, weight=1)
        side_stack.grid_rowconfigure((0, 1), weight=1)
        self.logic_card = SelectionLogicCard(side_stack)
        self.logic_card.grid(row=0, column=0, pady=(0, 10), sticky="nsew")
        self.repro_card = ReproducibilityCard(side_stack)
        self.repro_card.grid(row=1, column=0, pady=(10, 0), sticky="nsew")

        self.comparison = ImageComparisonFrame(self)
        self.comparison.grid(row=3, column=1, columnspan=2, padx=(10, CARD_PAD), pady=(0, CARD_PAD), sticky="nsew")

    def update_carrier(self, analysis: Mapping[str, Any] | None) -> None:
        if not analysis:
            self.carrier_text.configure(text="No carrier selected.")
            return
        lines = [
            f"Path: {Path(str(analysis['path'])).name}",
            f"Format: {analysis.get('format', 'unknown')}",
            f"Dimensions: {analysis.get('width', '-')} x {analysis.get('height', '-')}",
            f"Capacity: {int(analysis.get('capacity_bytes', 0)):,} bytes",
        ]
        if "robust_capacity_bytes" in analysis:
            lines.append(f"Robust JPEG Capacity: {int(analysis['robust_capacity_bytes']):,} bytes")
        self.carrier_text.configure(text="\n".join(lines))
        self.command_center.update_carrier(analysis)
        self.pipeline.set_progress(["W1"], active="W2")
        self.signal_flow.set_state(["cover"], active="crypto")

    def update_capacity(self, fraction: float, used_bytes: int, total_bytes: int) -> None:
        self.capacity_gauge.set(fraction)
        self.capacity_caption.configure(text=f"Estimated envelope: {used_bytes:,} / {total_bytes:,} bytes")

    def update_resistance(self, score: float | None) -> None:
        if score is None:
            self.resistance_badge.configure(text="Not Evaluated", fg_color="#303030")
            self.resistance_text.configure(text="Run the evaluation harness after embedding to compute PSNR, SSIM, ROC/AUC, and the unified Resistance Score.")
            return
        status = classify_resistance_score(score)
        self.resistance_badge.configure(text=f"{status['label']} | {score:.2f}/100", fg_color=status["gui_color"])
        self.resistance_text.configure(text=status["description"])
        self.command_center.update_resistance(score)


class EmbedFrame(ctk.CTkFrame):
    """Embedding workspace with carrier drop zone, payload, and policy view."""

    def __init__(self, master: ctk.CTkBaseClass, app: "StegoToolkitApp") -> None:
        super().__init__(master, fg_color=BG, corner_radius=0)
        self.app = app
        self.grid_columnconfigure(0, weight=2)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        left = ctk.CTkFrame(self, fg_color=BG)
        left.grid(row=0, column=0, rowspan=2, padx=(CARD_PAD, 10), pady=CARD_PAD, sticky="nsew")
        left.grid_columnconfigure(0, weight=1)
        left.grid_rowconfigure(2, weight=1)

        self.drop_zone = DropZoneFrame(left, on_pick=app.choose_cover)
        self.drop_zone.grid(row=0, column=0, sticky="ew")

        self.payload_card = CardFrame(left, title="Payload Workspace")
        self.payload_card.grid(row=1, column=0, pady=CARD_PAD, sticky="nsew")
        self.payload_card.grid_rowconfigure(1, weight=1)
        self.payload_text = ctk.CTkTextbox(
            self.payload_card,
            fg_color=INPUT,
            text_color=TEXT,
            border_color=BORDER,
            border_width=1,
            corner_radius=10,
            height=210,
            wrap="word",
            font=ctk.CTkFont(size=13),
        )
        self.payload_text.grid(row=1, column=0, padx=CARD_PAD, pady=(0, 14), sticky="nsew")
        self.payload_text.bind("<KeyRelease>", lambda _event: app.on_payload_changed())

        controls = ctk.CTkFrame(self.payload_card, fg_color=CARD)
        controls.grid(row=2, column=0, padx=CARD_PAD, pady=(0, 18), sticky="ew")
        controls.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(controls, text="Password", text_color=MUTED).grid(row=0, column=0, padx=(0, 10), sticky="w")
        self.password_entry = ctk.CTkEntry(
            controls,
            textvariable=app.embed_password_var,
            show="*",
            fg_color=INPUT,
            border_color=BORDER,
            text_color=TEXT,
            placeholder_text="Use a long passphrase",
        )
        self.password_entry.grid(row=0, column=1, sticky="ew")

        self.jpeg_var = ctk.BooleanVar(value=True)
        self.noise_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(controls, text="Expect JPEG retransmission", variable=self.jpeg_var, command=app.on_payload_changed).grid(
            row=1,
            column=0,
            columnspan=2,
            pady=(12, 4),
            sticky="w",
        )
        ctk.CTkCheckBox(controls, text="Expect noisy channel", variable=self.noise_var, command=app.on_payload_changed).grid(
            row=2,
            column=0,
            columnspan=2,
            sticky="w",
        )

        self.embed_button = ctk.CTkButton(
            self.payload_card,
            text="Encrypt and Embed",
            fg_color=GREEN,
            hover_color="#239860",
            height=42,
            command=app.embed_payload,
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self.embed_button.grid(row=3, column=0, padx=CARD_PAD, pady=(0, 12), sticky="ew")

        self.integrity_status = IntegrityStatus(self.payload_card)
        self.integrity_status.grid(row=4, column=0, padx=CARD_PAD, pady=(0, CARD_PAD), sticky="ew")

        right = ctk.CTkFrame(self, fg_color=BG)
        right.grid(row=0, column=1, rowspan=2, padx=(10, CARD_PAD), pady=CARD_PAD, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(2, weight=1)
        self.crypto_card = CryptoPipelineCard(right)
        self.crypto_card.grid(row=0, column=0, sticky="ew")
        self.capacity_card = CardFrame(right, title="Live Capacity")
        self.capacity_card.grid(row=1, column=0, pady=CARD_PAD, sticky="ew")
        self.capacity_gauge = CapacityGauge(self.capacity_card, size=156)
        self.capacity_gauge.grid(row=1, column=0, padx=18, pady=(0, 8))
        self.capacity_label = ctk.CTkLabel(self.capacity_card, text="0 / 0 bytes", text_color=MUTED)
        self.capacity_label.grid(row=2, column=0, padx=18, pady=(0, 18))

        self.logic_card = SelectionLogicCard(right, title="Decision Logic")
        self.logic_card.grid(row=2, column=0, sticky="nsew")

    def payload(self) -> str:
        return self.payload_text.get("1.0", "end-1c")

    def transforms(self) -> list[str]:
        transforms: list[str] = []
        if self.jpeg_var.get():
            transforms.append("jpeg_recompression")
        if self.noise_var.get():
            transforms.append("noise")
        return transforms

    def update_capacity(self, fraction: float, used_bytes: int, total_bytes: int) -> None:
        self.capacity_gauge.set(fraction)
        self.capacity_label.configure(text=f"{used_bytes:,} / {total_bytes:,} bytes")

    def update_crypto(self, password: str, embedded: bool = False) -> None:
        self.crypto_card.update_password(password, embedded=embedded)


class ExtractFrame(ctk.CTkFrame):
    """Authenticated extraction workspace."""

    def __init__(self, master: ctk.CTkBaseClass, app: "StegoToolkitApp") -> None:
        super().__init__(master, fg_color=BG, corner_radius=0)
        self.app = app
        self.grid_columnconfigure(0, weight=1)

        card = CardFrame(self, title="Extract Authenticated Payload")
        card.grid(row=0, column=0, padx=CARD_PAD, pady=CARD_PAD, sticky="new")
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text="Stego Image", text_color=MUTED).grid(row=1, column=0, padx=CARD_PAD, pady=(4, 10), sticky="w")
        self.stego_label = ctk.CTkLabel(card, text="No stego image selected", text_color=MUTED, anchor="w")
        self.stego_label.grid(row=1, column=1, padx=10, pady=(4, 10), sticky="ew")
        ctk.CTkButton(card, text="Browse", fg_color=BLUE, hover_color=BLUE_HOVER, command=app.choose_extract_stego).grid(
            row=1,
            column=2,
            padx=CARD_PAD,
            pady=(4, 10),
        )

        ctk.CTkLabel(card, text="Password", text_color=MUTED).grid(row=2, column=0, padx=CARD_PAD, pady=10, sticky="w")
        self.password_entry = ctk.CTkEntry(
            card,
            textvariable=app.extract_password_var,
            show="*",
            fg_color=INPUT,
            border_color=BORDER,
            text_color=TEXT,
        )
        self.password_entry.grid(row=2, column=1, columnspan=2, padx=(10, CARD_PAD), pady=10, sticky="ew")

        ctk.CTkLabel(card, text="Output File", text_color=MUTED).grid(row=3, column=0, padx=CARD_PAD, pady=10, sticky="w")
        self.output_label = ctk.CTkLabel(card, text="recovered_payload.bin", text_color=MUTED, anchor="w")
        self.output_label.grid(row=3, column=1, padx=10, pady=10, sticky="ew")
        ctk.CTkButton(card, text="Save As", fg_color=BLUE, hover_color=BLUE_HOVER, command=app.choose_extract_output).grid(
            row=3,
            column=2,
            padx=CARD_PAD,
            pady=10,
        )

        ctk.CTkButton(
            card,
            text="Extract and Verify",
            fg_color=GREEN,
            hover_color="#239860",
            height=42,
            command=app.extract_payload,
            font=ctk.CTkFont(size=14, weight="bold"),
        ).grid(row=4, column=0, columnspan=3, padx=CARD_PAD, pady=(18, CARD_PAD), sticky="ew")

        self.result_box = ctk.CTkTextbox(
            self,
            height=270,
            fg_color=INPUT,
            text_color=TEXT,
            border_color=BORDER,
            border_width=1,
            corner_radius=10,
            font=ctk.CTkFont(size=13),
        )
        self.result_box.grid(row=1, column=0, padx=CARD_PAD, pady=(0, CARD_PAD), sticky="nsew")
        self.result_box.insert("1.0", "Authenticated extraction output will appear here.")
        self.result_box.configure(state="disabled")

    def update_stego_label(self, path: Path | None) -> None:
        self.stego_label.configure(text=path.name if path else "No stego image selected")

    def update_output_label(self, path: Path | None) -> None:
        self.output_label.configure(text=str(path) if path else "recovered_payload.bin")

    def set_result(self, text: str) -> None:
        self.result_box.configure(state="normal")
        self.result_box.delete("1.0", "end")
        self.result_box.insert("1.0", text)
        self.result_box.configure(state="disabled")


class EvaluationFrame(ctk.CTkFrame):
    """Evaluation harness view for PSNR, SSIM, ROC/AUC, and resistance score."""

    def __init__(self, master: ctk.CTkBaseClass, app: "StegoToolkitApp") -> None:
        super().__init__(master, fg_color=BG, corner_radius=0)
        self.app = app
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self.pipeline = PipelineStageStrip(self, title="Evaluation Protocol Pipeline")
        self.pipeline.grid(row=0, column=0, columnspan=2, padx=CARD_PAD, pady=(CARD_PAD, 10), sticky="ew")
        self.pipeline.set_progress([])
        controls = CardFrame(self, title="Evaluation Harness")
        controls.grid(row=1, column=0, columnspan=2, padx=CARD_PAD, pady=(10, CARD_PAD), sticky="ew")
        controls.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(controls, text="Cover", text_color=MUTED).grid(row=1, column=0, padx=CARD_PAD, pady=8, sticky="w")
        self.cover_label = ctk.CTkLabel(controls, text="No cover selected", text_color=MUTED, anchor="w")
        self.cover_label.grid(row=1, column=1, padx=10, pady=8, sticky="ew")
        ctk.CTkButton(controls, text="Browse", fg_color=BLUE, hover_color=BLUE_HOVER, command=app.choose_cover).grid(
            row=1,
            column=2,
            padx=CARD_PAD,
            pady=8,
        )
        ctk.CTkLabel(controls, text="Stego", text_color=MUTED).grid(row=2, column=0, padx=CARD_PAD, pady=8, sticky="w")
        self.stego_label = ctk.CTkLabel(controls, text="No stego selected", text_color=MUTED, anchor="w")
        self.stego_label.grid(row=2, column=1, padx=10, pady=8, sticky="ew")
        ctk.CTkButton(controls, text="Browse", fg_color=BLUE, hover_color=BLUE_HOVER, command=app.choose_evaluation_stego).grid(
            row=2,
            column=2,
            padx=CARD_PAD,
            pady=8,
        )
        ctk.CTkButton(
            controls,
            text="Run Evaluation and Write report.md",
            fg_color=GREEN,
            hover_color="#239860",
            height=40,
            command=app.run_evaluation,
            font=ctk.CTkFont(size=14, weight="bold"),
        ).grid(row=3, column=0, columnspan=3, padx=CARD_PAD, pady=(16, CARD_PAD), sticky="ew")

        self.results = CardFrame(self, title="Visual Resistance & Quality")
        self.results.grid(row=2, column=0, padx=(CARD_PAD, 10), pady=(0, 10), sticky="nsew")
        self.results.grid_rowconfigure(3, weight=1)
        gauges = ctk.CTkFrame(self.results, fg_color=CARD)
        gauges.grid(row=1, column=0, padx=CARD_PAD, pady=(0, 12), sticky="ew")
        gauges.grid_columnconfigure((0, 1), weight=1)
        self.resistance_gauge = LinearMetricGauge(gauges, "Resistance Score")
        self.resistance_gauge.grid(row=0, column=0, padx=(0, 12), sticky="ew")
        self.ssim_gauge = LinearMetricGauge(gauges, "Image Fidelity (SSIM)", suffix="")
        self.ssim_gauge.grid(row=0, column=1, padx=(12, 0), sticky="ew")
        self.fidelity_badge = ctk.CTkLabel(
            self.results,
            text="High-Fidelity badge appears at SSIM > 0.98",
            fg_color="#303030",
            text_color=MUTED,
            corner_radius=16,
            padx=12,
            pady=7,
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self.fidelity_badge.grid(row=2, column=0, padx=CARD_PAD, pady=(0, 12), sticky="w")
        self.result_box = ctk.CTkTextbox(
            self.results,
            fg_color=INPUT,
            text_color=TEXT,
            border_color=BORDER,
            border_width=1,
            corner_radius=10,
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.result_box.grid(row=3, column=0, padx=CARD_PAD, pady=(0, CARD_PAD), sticky="nsew")
        self.set_results("Run the evaluation harness to populate PSNR, SSIM, ROC/AUC, and Resistance Score.")

        self.logic_card = SelectionLogicCard(self, title="Decision Logic")
        self.logic_card.grid(row=3, column=0, padx=(CARD_PAD, 10), pady=(10, CARD_PAD), sticky="nsew")

        self.comparison = ImageComparisonFrame(self)
        self.comparison.grid(row=2, column=1, rowspan=2, padx=(10, CARD_PAD), pady=(0, CARD_PAD), sticky="nsew")

    def update_cover_label(self, path: Path | None) -> None:
        self.cover_label.configure(text=path.name if path else "No cover selected")

    def update_stego_label(self, path: Path | None) -> None:
        self.stego_label.configure(text=path.name if path else "No stego selected")

    def set_results(self, text: str) -> None:
        self.result_box.configure(state="normal")
        self.result_box.delete("1.0", "end")
        self.result_box.insert("1.0", text)
        self.result_box.configure(state="disabled")

    def update_metric_gauges(self, resistance_score: float, ssim: float) -> None:
        self.resistance_gauge.set_metric(resistance_score, max_value=100.0)
        self.ssim_gauge.set_metric(ssim, max_value=1.0)
        self.pipeline.set_progress(["W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8"])
        if ssim > 0.98:
            self.fidelity_badge.configure(text="High-Fidelity | SSIM > 0.98", fg_color=GREEN, text_color=WHITE)
        else:
            self.fidelity_badge.configure(text="Fidelity below high-confidence threshold", fg_color=YELLOW, text_color=TEXT)


class StegoToolkitApp(DragDropCTk):
    """Professional GUI shell for the secure steganography toolkit."""

    def __init__(self) -> None:
        super().__init__(fg_color=BG)
        self.title("Secure Adaptive Image Steganography Toolkit")
        self.geometry("1320x860")
        self.minsize(1100, 720)
        self.toolkit = StegoToolkit()
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="gui-worker")
        self.toast = ToastManager(self)
        self.cover_path: Path | None = None
        self.stego_path: Path | None = None
        self.extract_stego_path: Path | None = None
        self.extract_output_path: Path | None = None
        self.carrier_analysis: dict[str, Any] | None = None
        self.current_config: dict[str, Any] | None = None
        self.current_trace: list[str] = []
        self.embed_password_var = ctk.StringVar(value="")
        self.extract_password_var = ctk.StringVar(value="")
        self.embed_password_var.trace_add("write", lambda *_args: self.on_password_changed())
        self.extract_password_var.trace_add("write", lambda *_args: self.on_extract_password_changed())

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self._build_shell()
        self.header.update_password("")
        self.sidebar.update_security("")
        self._embed_frame().update_crypto("")
        self._enable_drop_target()
        self.switch_view("dashboard")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_shell(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.sidebar = SidebarFrame(self, on_select=self.switch_view)
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.header = SecurityHeader(self)
        self.header.grid(row=0, column=1, sticky="ew")

        self.content = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.content.grid(row=1, column=1, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self.frames: dict[str, ctk.CTkFrame] = {
            "dashboard": DashboardFrame(self.content, self),
            "embed": EmbedFrame(self.content, self),
            "extract": ExtractFrame(self.content, self),
            "evaluate": EvaluationFrame(self.content, self),
        }
        for frame in self.frames.values():
            frame.grid(row=0, column=0, sticky="nsew")

    def switch_view(self, key: str) -> None:
        self.frames[key].tkraise()
        self.sidebar.set_active(key)
        self._fade_in()

    def choose_cover(self) -> None:
        path = filedialog.askopenfilename(
            title="Select carrier image",
            filetypes=[("Images", "*.png *.jpg *.jpeg"), ("All files", "*.*")],
        )
        if path:
            self.set_cover(Path(path))

    def choose_extract_stego(self) -> None:
        path = filedialog.askopenfilename(
            title="Select stego image",
            filetypes=[("Images", "*.png *.jpg *.jpeg"), ("All files", "*.*")],
        )
        if path:
            self.extract_stego_path = Path(path)
            extract_frame = self.frames["extract"]
            if isinstance(extract_frame, ExtractFrame):
                extract_frame.update_stego_label(self.extract_stego_path)

    def choose_extract_output(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save recovered payload",
            defaultextension=".bin",
            filetypes=[("Binary payload", "*.bin"), ("All files", "*.*")],
        )
        if path:
            self.extract_output_path = Path(path)
            extract_frame = self.frames["extract"]
            if isinstance(extract_frame, ExtractFrame):
                extract_frame.update_output_label(self.extract_output_path)

    def choose_evaluation_stego(self) -> None:
        path = filedialog.askopenfilename(
            title="Select stego image",
            filetypes=[("Images", "*.png *.jpg *.jpeg"), ("All files", "*.*")],
        )
        if path:
            self.set_stego(Path(path), source="evaluation")

    def set_cover(self, path: Path) -> None:
        try:
            analysis = self.toolkit.analyze_carrier(path)
        except Exception as exc:
            self.toast.show(f"Carrier analysis failed: {exc}", kind="error")
            return
        self.cover_path = path
        self.carrier_analysis = dict(analysis)
        dashboard = self.frames["dashboard"]
        evaluation = self.frames["evaluate"]
        if isinstance(dashboard, DashboardFrame):
            dashboard.update_carrier(analysis)
            dashboard.comparison.set_cover(path)
        if isinstance(evaluation, EvaluationFrame):
            evaluation.update_cover_label(path)
            evaluation.comparison.set_cover(path)
        self._refresh_evaluation_pipeline()
        self.on_payload_changed()
        self.toast.show("Carrier analysis complete.", kind="success")

    def set_stego(self, path: Path, *, source: Literal["embed", "evaluation"]) -> None:
        self.stego_path = path
        dashboard = self.frames["dashboard"]
        evaluation = self.frames["evaluate"]
        if isinstance(dashboard, DashboardFrame):
            dashboard.comparison.set_stego(path)
        if isinstance(evaluation, EvaluationFrame):
            evaluation.update_stego_label(path)
            evaluation.comparison.set_stego(path)
        self._refresh_evaluation_pipeline()
        if source == "embed":
            self.extract_stego_path = path
            extract_frame = self.frames["extract"]
            if isinstance(extract_frame, ExtractFrame):
                extract_frame.update_stego_label(path)

    def on_password_changed(self) -> None:
        self.header.update_password(self.embed_password_var.get())
        self.sidebar.update_security(self.embed_password_var.get())
        self._embed_frame().update_crypto(self.embed_password_var.get())
        dashboard = self.frames["dashboard"]
        if isinstance(dashboard, DashboardFrame):
            dashboard.command_center.update_crypto(self.embed_password_var.get())
        self.on_payload_changed()

    def on_extract_password_changed(self) -> None:
        password = self.extract_password_var.get()
        self.header.update_password(password)
        self.sidebar.update_security(password)

    def on_payload_changed(self) -> None:
        payload = self._embed_frame().payload()
        used_bytes = _estimated_envelope_bytes(payload)
        capacity_bytes = int((self.carrier_analysis or {}).get("capacity_bytes", 0))
        fraction = used_bytes / capacity_bytes if capacity_bytes else 0.0
        self._embed_frame().update_capacity(fraction, used_bytes, capacity_bytes)
        dashboard = self.frames["dashboard"]
        if isinstance(dashboard, DashboardFrame):
            dashboard.update_capacity(fraction, used_bytes, capacity_bytes)
        self._update_selector_preview(used_bytes * 8)

    def embed_payload(self) -> None:
        payload = self._embed_frame().payload().encode("utf-8")
        password = self.embed_password_var.get()
        if not self.cover_path:
            self.toast.show("Select a carrier image before embedding.", kind="warning")
            return
        if not payload:
            self.toast.show("Type a payload before embedding.", kind="warning")
            return
        if not password:
            self.toast.show("Enter a password before embedding.", kind="warning")
            return
        output_path = self._default_stego_path(self.cover_path)
        transforms = self._embed_frame().transforms()
        self._embed_frame().integrity_status.set_verifying("Embedding encrypted envelope")
        self._embed_frame().update_crypto(password)
        dashboard = self.frames["dashboard"]
        if isinstance(dashboard, DashboardFrame):
            dashboard.pipeline.set_progress(["W1", "W2", "W3"], active="W4")
            dashboard.signal_flow.set_state(["cover", "crypto", "selector"], active="embed")
        self.toast.show("Embedding started. Argon2id and AES-GCM are active.", kind="info")
        future = self.executor.submit(
            self.toolkit.protect_and_embed,
            self.cover_path,
            payload,
            password,
            transforms,
            output_path,
        )
        future.add_done_callback(lambda completed: self.after(0, lambda: self._handle_embed_result(completed, payload, password)))

    def extract_payload(self) -> None:
        stego_path = self.extract_stego_path or self.stego_path
        password = self.extract_password_var.get()
        if not stego_path:
            self.toast.show("Select a stego image before extraction.", kind="warning")
            return
        if not password:
            self.toast.show("Enter the extraction password.", kind="warning")
            return
        output = self.extract_output_path or (stego_path.with_name("recovered_payload.bin"))
        self.toast.show("Authenticated extraction started.", kind="info")
        future = self.executor.submit(self.toolkit.extract_and_verify, stego_path, password)
        future.add_done_callback(lambda completed: self.after(0, lambda: self._handle_extract_result(completed, output)))

    def run_evaluation(self) -> None:
        if not self.cover_path or not self.stego_path:
            self.toast.show("Choose both cover and stego images for evaluation.", kind="warning")
            return
        self.toast.show("Evaluation harness running.", kind="info")
        dashboard = self.frames["dashboard"]
        evaluation = self.frames["evaluate"]
        if isinstance(dashboard, DashboardFrame):
            dashboard.pipeline.set_progress(["W1", "W2", "W3", "W4"], active="W5")
            dashboard.signal_flow.set_state(["cover", "crypto", "selector", "embed", "verify"], active="evaluate")
        if isinstance(evaluation, EvaluationFrame):
            evaluation.pipeline.set_progress(["W1", "W2", "W3", "W4"], active="W5")
        future = self.executor.submit(self.toolkit.run_evaluation, self.cover_path, self.stego_path)
        future.add_done_callback(lambda completed: self.after(0, lambda: self._handle_evaluation_result(completed)))

    def _handle_embed_result(self, completed: Any, payload: bytes, password: str) -> None:
        try:
            result = completed.result()
        except Exception as exc:
            self._embed_frame().integrity_status.set_failed("Embedding failed")
            self.toast.show(f"Embedding failed: {exc}", kind="error")
            return
        self.current_config = dict(result.get("selected_config", {}))
        self.current_trace = list(result.get("justification_trace", []))
        stego_path = Path(str(result["stego_path"]))
        self.set_stego(stego_path, source="embed")
        self._sync_selector_cards()
        dashboard = self.frames["dashboard"]
        if isinstance(dashboard, DashboardFrame):
            dashboard.repro_card.update_embedding(result)
            dashboard.pipeline.set_progress(["W1", "W2", "W3", "W4"], active="W6")
            dashboard.signal_flow.set_state(["cover", "crypto", "selector", "embed"], active="verify")
        self.toast.show(f"Stego image written: {stego_path.name}", kind="success")
        self._embed_frame().integrity_status.set_verifying("Trial extraction running")
        verify_future = self.executor.submit(self._verify_integrity, stego_path, password, payload)
        verify_future.add_done_callback(lambda verified: self.after(0, lambda: self._handle_integrity_result(verified)))

    def _handle_extract_result(self, completed: Any, output: Path) -> None:
        extract_frame = self.frames["extract"]
        try:
            payload = completed.result()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(payload)
        except Exception as exc:
            self.toast.show(f"Extraction failed: {exc}", kind="error")
            if isinstance(extract_frame, ExtractFrame):
                extract_frame.set_result(f"Authentication failed or payload could not be recovered.\n\n{exc}")
            return
        preview = payload[:512].decode("utf-8", errors="replace")
        message = f"Recovered {len(payload):,} bytes.\nWritten to: {output}\n\nPreview:\n{preview}"
        if isinstance(extract_frame, ExtractFrame):
            extract_frame.set_result(message)
        self.toast.show("Payload authenticated and recovered.", kind="success")

    def _handle_evaluation_result(self, completed: Any) -> None:
        evaluation = self.frames["evaluate"]
        dashboard = self.frames["dashboard"]
        try:
            report = completed.result()
            report_path = self.toolkit.evaluator.write_markdown_report(report, Path("report.md"))
        except Exception as exc:
            self.toast.show(f"Evaluation failed: {exc}", kind="error")
            if isinstance(evaluation, EvaluationFrame):
                evaluation.set_results(f"Evaluation failed.\n\n{exc}")
            return
        quality = dict(report["quality_metrics"])
        detectability = dict(report["detectability"])
        resistance = dict(report["resistance_score"])
        score = float(resistance["final_score"])
        text = "\n".join(
            [
                f"PSNR: {float(quality['psnr']):.2f} dB",
                f"SSIM: {float(quality['ssim']):.6f}",
                f"ROC AUC: {float(detectability['roc_auc']):.6f}",
                f"TPR @ 1.0% FPR: {float(detectability['tpr_at_1_fpr']):.6f}",
                f"TPR @ 0.1% FPR: {float(detectability['tpr_at_0_1_fpr']):.6f}",
                f"Resistance Score: {score:.2f}/100",
                f"Markdown Report: {report_path.resolve()}",
            ]
        )
        if isinstance(evaluation, EvaluationFrame):
            evaluation.set_results(text)
            evaluation.update_metric_gauges(score, float(quality["ssim"]))
        if isinstance(dashboard, DashboardFrame):
            dashboard.update_resistance(score)
            dashboard.repro_card.update_evaluation(report, report_path)
            dashboard.pipeline.set_progress(["W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8"])
            dashboard.signal_flow.set_state(["cover", "crypto", "selector", "embed", "verify", "evaluate"])
        self.current_config = dict(report.get("selected_config", {}))
        self.current_trace = list(report.get("justification_trace", []))
        self._sync_selector_cards()
        self.toast.show("Evaluation complete. report.md updated.", kind="success")

    def _update_selector_preview(self, payload_bits: int) -> None:
        if not self.carrier_analysis:
            self.current_config = None
            self.current_trace = []
            self._sync_selector_cards()
            return
        try:
            config, trace = self.toolkit.selector.select_configuration(
                carrier_metadata=dict(self.carrier_analysis.get("metadata", self.carrier_analysis)),
                payload_size_bits=max(payload_bits, 1),
                expected_transformations=self._embed_frame().transforms(),
            )
        except Exception as exc:
            self.current_config = {"engine_name": "Policy Blocked"}
            self.current_trace = [str(exc)]
        else:
            self.current_config = dict(config)
            self.current_trace = list(trace)
        self._sync_selector_cards()

    def _sync_selector_cards(self) -> None:
        dashboard = self.frames["dashboard"]
        embed = self.frames["embed"]
        evaluation = self.frames["evaluate"]
        if isinstance(dashboard, DashboardFrame):
            dashboard.logic_card.update_trace(self.current_config, self.current_trace)
            dashboard.command_center.update_engine(self.current_config)
        if isinstance(embed, EmbedFrame):
            embed.logic_card.update_trace(self.current_config, self.current_trace)
        if isinstance(evaluation, EvaluationFrame):
            evaluation.logic_card.update_trace(self.current_config, self.current_trace)

    def _verify_integrity(self, stego_path: Path, password: str, expected_payload: bytes) -> None:
        recovered = self.toolkit.extract_and_verify(stego_path, password)
        if not hmac.compare_digest(recovered, expected_payload):
            raise RuntimeError("Trial extraction completed but recovered bytes did not match the original payload.")

    def _handle_integrity_result(self, completed: Any) -> None:
        try:
            completed.result()
        except Exception as exc:
            self._embed_frame().integrity_status.set_failed("Integrity check failed")
            self.toast.show(f"Integrity verification failed: {exc}", kind="error")
            return
        self._embed_frame().integrity_status.set_verified()
        self._embed_frame().update_crypto(self.embed_password_var.get(), embedded=True)
        dashboard = self.frames["dashboard"]
        if isinstance(dashboard, DashboardFrame):
            dashboard.pipeline.set_progress(["W1", "W2", "W3", "W4", "W6"])
            dashboard.command_center.update_crypto(self.embed_password_var.get(), embedded=True)
            dashboard.signal_flow.set_state(["cover", "crypto", "selector", "embed", "verify"])
        self._refresh_evaluation_pipeline()
        self.toast.show("Trial extraction matched original payload. Data verified.", kind="success")

    def _refresh_evaluation_pipeline(self) -> None:
        evaluation = self.frames["evaluate"]
        if not isinstance(evaluation, EvaluationFrame):
            return
        completed: list[str] = []
        if self.cover_path:
            completed.append("W1")
        if self.stego_path:
            completed.extend(["W2", "W3", "W4"])
        evaluation.pipeline.set_progress(completed)

    def _fade_in(self) -> None:
        overlay = ctk.CTkFrame(self.content, fg_color=SURFACE, corner_radius=0)
        overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        overlay.lift()
        colors = ["#1e1e1e", "#1a1a1a", "#161616", BG]

        def step(index: int = 0) -> None:
            if index >= len(colors):
                overlay.destroy()
                return
            overlay.configure(fg_color=colors[index])
            self.after(24, lambda: step(index + 1))

        step()

    def _enable_drop_target(self) -> None:
        if not self.enable_native_dnd() or DND_FILES is None:
            return
        try:
            self.drop_target_register(DND_FILES)  # type: ignore[attr-defined]
            self.dnd_bind("<<DropEnter>>", self._handle_drop_enter)  # type: ignore[attr-defined]
            self.dnd_bind("<<DropLeave>>", self._handle_drop_leave)  # type: ignore[attr-defined]
            self.dnd_bind("<<Drop>>", self._handle_drop)  # type: ignore[attr-defined]
        except Exception as exc:  # pragma: no cover - platform specific
            logger.info("Native drag/drop registration failed: %s", exc)

    def _handle_drop_enter(self, _event: Any) -> str:
        self._embed_frame().drop_zone.set_hover(True)
        return "copy"

    def _handle_drop_leave(self, _event: Any) -> str:
        self._embed_frame().drop_zone.set_hover(False)
        return "copy"

    def _handle_drop(self, event: Any) -> str:
        self._embed_frame().drop_zone.set_hover(False)
        raw = str(getattr(event, "data", ""))
        paths = self.tk.splitlist(raw)
        if paths:
            self.set_cover(Path(paths[0]))
        return "copy"

    def _embed_frame(self) -> EmbedFrame:
        frame = self.frames["embed"]
        if not isinstance(frame, EmbedFrame):
            raise RuntimeError("Embed frame was not initialized correctly.")
        return frame

    def _default_stego_path(self, cover_path: Path) -> Path:
        suffix = cover_path.suffix.lower()
        return cover_path.with_name(f"{cover_path.stem}_stego{suffix}")

    def _on_close(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.destroy()


def _password_strength(password: str) -> tuple[str, str, bool]:
    if not password:
        return "No Password", RED, False
    checks = [
        len(password) >= 12,
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[^A-Za-z0-9]", password)),
    ]
    score = sum(checks)
    if score >= 5:
        return "Strong", GREEN, True
    if score >= 3:
        return "Moderate", YELLOW, False
    return "Weak", YELLOW, False


def _estimated_envelope_bytes(payload: str) -> int:
    if not payload:
        return 0
    return len(payload.encode("utf-8")) + ENCRYPTED_ENVELOPE_OVERHEAD_BYTES


def _justification_badge(config: Mapping[str, Any]) -> str:
    engine = str(config.get("engine_name", ""))
    kwargs = config.get("embed_kwargs", {})
    robust = isinstance(kwargs, Mapping) and bool(kwargs.get("robust_mode"))
    if "JPEG" in engine and robust:
        return "Optimized for JPEG Retransmission"
    if "JPEG" in engine:
        return "DCT Domain Policy Selected"
    if "PNG" in engine:
        return "Spatial LSB Matching Selected"
    return "Policy Decision Ready"


def _format_policy_audit_log(config: Mapping[str, Any], trace: Sequence[str]) -> str:
    carrier = str(config.get("carrier_format", "UNKNOWN")).upper()
    engine = str(config.get("engine_name", "Unknown Engine"))
    kwargs = config.get("embed_kwargs", {})
    robust = isinstance(kwargs, Mapping) and bool(kwargs.get("robust_mode"))
    if carrier == "JPEG":
        risk = "High Recompression risk" if robust else "Standard recompression risk"
        decision = "Selecting DCT-Adaptive Engine to ensure persistence"
    elif carrier == "PNG":
        risk = "Spatial carrier with low transform risk"
        decision = "Selecting LSB-Matching Engine for high-capacity embedding"
    else:
        risk = "Carrier policy evaluated"
        decision = f"Selecting {engine}"
    lines = [
        f"[POLICY]: {carrier} Carrier detected -> {risk} -> {decision}.",
        f"[ENGINE]: {engine}",
        "",
        "[TRACE]:",
    ]
    lines.extend(f"  - {line}" for line in trace)
    return "\n".join(lines)


def _load_ctk_preview(path: Path, size: tuple[int, int]) -> ctk.CTkImage:
    with Image.open(path) as image:
        return _image_to_ctk_preview(image.copy(), size)


def _image_to_ctk_preview(image: Image.Image, size: tuple[int, int]) -> ctk.CTkImage:
    preview = ImageOps.contain(image.convert("RGB"), size, Image.Resampling.LANCZOS)
    canvas = Image.new("RGB", size, INPUT)
    offset = ((size[0] - preview.width) // 2, (size[1] - preview.height) // 2)
    canvas.paste(preview, offset)
    return ctk.CTkImage(light_image=canvas, dark_image=canvas, size=size)


def _difference_map(cover_path: Path, stego_path: Path) -> Image.Image:
    with Image.open(cover_path) as cover_image, Image.open(stego_path) as stego_image:
        cover = cover_image.convert("RGB")
        stego = stego_image.convert("RGB")
        if cover.size != stego.size:
            stego = stego.resize(cover.size, Image.Resampling.LANCZOS)
        diff = ImageChops.difference(cover, stego)
        diff = ImageEnhance.Contrast(diff).enhance(12.0)
        gray = ImageOps.grayscale(diff)
        return ImageOps.colorize(gray, black="#050505", white=RED, mid=BLUE)


def _hex_rgba(hex_color: str, alpha: int) -> tuple[int, int, int, int]:
    clean = hex_color.lstrip("#")
    return int(clean[0:2], 16), int(clean[2:4], 16), int(clean[4:6], 16), alpha


def main() -> int:
    configure_logging(log_file=Path("logs/stegtoolkit-audit.log"), verbose=False)
    app = StegoToolkitApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
