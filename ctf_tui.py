"""Rich-backed live terminal UI with bounded output and keyboard scrolling."""

from __future__ import annotations

from collections import deque
import os
import re
import shutil
import sys
import threading
import time
from typing import TextIO

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

if os.name != "nt":
    import select
    import termios
    import tty


ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
RICH_STYLES = {
    "dim": "dim",
    "think": "yellow dim",
    "say": "cyan",
    "tool": "magenta",
    "ok": "green",
    "err": "red",
    "flag": "bold green",
    "info": "blue",
    "phase": "bold blue",
}
Segment = tuple[str, str]


class TerminalTui:
    """Render a fixed status pane and a bounded, keyboard-scrollable activity pane."""

    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        ansi_enabled: bool = True,
        max_activity_chars: int = 24000,
        input_stream: TextIO | None = None,
    ) -> None:
        self.stream = stream or sys.stdout
        self.input_stream = input_stream or sys.stdin
        self.ansi_enabled = ansi_enabled
        self.active = False
        self.status_lines: list[str] = []
        self.lines: deque[list[Segment]] = deque(maxlen=600)
        self.current_line: list[Segment] = []
        self.activity_chars = 0
        self.max_activity_chars = max(1000, int(max_activity_chars))
        self.max_line_chars = min(self.max_activity_chars, 4000)
        self.scroll_offset = 0
        self.console: Console | None = None
        self.live: Live | None = None
        self.last_render_at = 0.0
        self.input_stop = threading.Event()
        self.input_thread: threading.Thread | None = None
        self.lock = threading.RLock()
        self.min_width = 80
        self.min_height = 12

    @staticmethod
    def _clean(text: str) -> str:
        text = ANSI_ESCAPE.sub("", str(text)).replace("\r", "")
        return text.replace("\x00", "")

    @staticmethod
    def _line_length(line: list[Segment]) -> int:
        return sum(len(value) for value, _ in line)

    def _trim_activity(self) -> None:
        current_chars = self._line_length(self.current_line)
        while self.lines and self.activity_chars + current_chars > self.max_activity_chars:
            self.activity_chars -= self._line_length(self.lines.popleft())

    def _append_segment(self, text: str, color: str) -> None:
        text = self._clean(text)
        if not text:
            return
        current_chars = self._line_length(self.current_line)
        available = self.max_line_chars - current_chars
        if available <= 0:
            return
        if len(text) > available:
            text = text[: max(0, available - 1)] + "…"
        if self.current_line and self.current_line[-1][1] == color:
            previous, _ = self.current_line[-1]
            self.current_line[-1] = (previous + text, color)
        else:
            self.current_line.append((text, color))
        self._trim_activity()

    def _finish_line(self) -> None:
        line = self.current_line or [("", "")]
        self.lines.append(line)
        self.activity_chars += self._line_length(line)
        self.current_line = []
        self._trim_activity()

    def _size(self) -> tuple[int, int]:
        size = shutil.get_terminal_size(fallback=(120, 30))
        return max(1, size.columns), max(1, size.lines)

    def _input_is_tty(self) -> bool:
        isatty = getattr(self.input_stream, "isatty", None)
        return callable(isatty) and bool(isatty())

    def start(self) -> bool:
        output_isatty = getattr(self.stream, "isatty", None)
        if not self.ansi_enabled or not callable(output_isatty) or not output_isatty():
            return False
        width, height = self._size()
        if width < self.min_width or height < self.min_height:
            return False
        self.console = Console(
            file=self.stream,
            force_terminal=True,
            color_system="standard",
            soft_wrap=False,
            emoji=True,
        )
        try:
            self.live = Live(
                self._renderable(),
                console=self.console,
                screen=True,
                transient=False,
                auto_refresh=True,
                refresh_per_second=12,
            )
            self.live.start(refresh=True)
            self.active = True
            self._start_input_reader()
            return True
        except Exception:
            self.live = None
            self.console = None
            self.active = False
            return False

    def _start_input_reader(self) -> None:
        if not self._input_is_tty():
            return
        self.input_stop.clear()
        target = self._windows_input_loop if os.name == "nt" else self._posix_input_loop
        self.input_thread = threading.Thread(target=target, name="ctf-tui-input", daemon=True)
        self.input_thread.start()

    def stop(self) -> None:
        if not self.active:
            return
        recent = self.plain_recent(6)
        self.input_stop.set()
        if self.input_thread is not None:
            self.input_thread.join(timeout=0.5)
        self.input_thread = None
        self.render(refresh=True, force=True)
        if self.live is not None:
            self.live.stop()
        self.live = None
        self.console = None
        self.active = False
        if recent:
            try:
                self.stream.write("\n" + "\n".join(recent) + "\n")
                self.stream.flush()
            except UnicodeEncodeError:
                encoding = getattr(self.stream, "encoding", None) or "utf-8"
                safe = ("\n" + "\n".join(recent) + "\n").encode(encoding, errors="replace").decode(encoding)
                self.stream.write(safe)
                self.stream.flush()

    def write(self, text: str, color: str = "", end: str = "\n") -> None:
        payload = self._clean(text) + self._clean(end)
        with self.lock:
            pieces = payload.split("\n")
            for index, piece in enumerate(pieces):
                self._append_segment(piece, color)
                if index < len(pieces) - 1:
                    self._finish_line()
        self.render()

    def set_status(self, lines: list[str]) -> None:
        with self.lock:
            self.status_lines = [self._clean(line)[:500] for line in lines]
        self.render(refresh=True, force=True)

    def _handle_key(self, key: str) -> None:
        with self.lock:
            if key == "up":
                self.scroll_offset += 3
            elif key == "down":
                self.scroll_offset = max(0, self.scroll_offset - 3)
            elif key == "pageup":
                self.scroll_offset += max(5, self._size()[1] // 2)
            elif key == "pagedown":
                self.scroll_offset = max(0, self.scroll_offset - max(5, self._size()[1] // 2))
            elif key == "home":
                self.scroll_offset = 10**9
            elif key == "end":
                self.scroll_offset = 0
            else:
                return
        self.render(refresh=True, force=True)

    def _windows_input_loop(self) -> None:
        import msvcrt

        extended = {
            "H": "up",
            "P": "down",
            "I": "pageup",
            "Q": "pagedown",
            "G": "home",
            "O": "end",
        }
        while not self.input_stop.is_set():
            if msvcrt.kbhit():
                key = msvcrt.getwch()
                if key in ("\x00", "\xe0"):
                    key = extended.get(msvcrt.getwch(), "")
                elif key in ("k", "K"):
                    key = "up"
                elif key in ("j", "J"):
                    key = "down"
                elif key == " ":
                    key = "pagedown"
                else:
                    key = ""
                self._handle_key(key)
            time.sleep(0.03)

    def _posix_input_loop(self) -> None:
        fd: int
        try:
            fd = self.input_stream.fileno()
            previous = termios.tcgetattr(fd)
            tty.setcbreak(fd)
        except (AttributeError, OSError, termios.error):
            return
        try:
            while not self.input_stop.is_set():
                ready, _, _ = select.select([fd], [], [], 0.1)
                if not ready:
                    continue
                first = os.read(fd, 1)
                key = self._decode_posix_key(fd, first)
                self._handle_key(key)
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, previous)
            except (OSError, termios.error):
                pass

    @staticmethod
    def _decode_posix_key(fd: int, first: bytes) -> str:
        if first != b"\x1b":
            return {b"k": "up", b"j": "down", b" ": "pagedown"}.get(first, "")
        sequence = first
        for _ in range(3):
            ready, _, _ = select.select([fd], [], [], 0.02)
            if not ready:
                break
            sequence += os.read(fd, 1)
            if sequence.endswith(b"~"):
                break
        return {
            b"\x1b[A": "up",
            b"\x1b[B": "down",
            b"\x1b[5~": "pageup",
            b"\x1b[6~": "pagedown",
            b"\x1b[H": "home",
            b"\x1b[F": "end",
        }.get(sequence, "")

    def _status_text(self) -> Text:
        text = Text()
        for index, line in enumerate(self.status_lines):
            if index:
                text.append("\n")
            if ":" in line:
                label, value = line.split(":", 1)
                text.append(label + ":", style="bold bright_cyan")
                text.append(value)
            else:
                text.append(line, style="bold bright_white")
        if not self.status_lines:
            text.append("等待 Agent 状态…", style="dim")
        text.append("\n\n")
        if self.scroll_offset:
            text.append(f"滚动: 上移 {self.scroll_offset} 行", style="bold yellow")
            text.append("\nEnd = 回到尾部", style="dim")
        else:
            text.append("滚动: 跟随尾部", style="bold green")
            text.append("\n↑↓ / PgUp/PgDn 查看历史", style="dim")
        return text

    def _segments_to_text(self, line: list[Segment]) -> Text:
        text = Text()
        for value, color in line:
            text.append(value, style=RICH_STYLES.get(color, ""))
        return text

    def _activity_visual_lines(self, width: int) -> list[Text]:
        source = list(self.lines)
        if self.current_line:
            source.append(self.current_line)
        visual: list[Text] = []
        for line in source:
            rich_line = self._segments_to_text(line)
            wrapped = rich_line.wrap(self.console, width, overflow="fold") if self.console is not None else [rich_line]
            visual.extend(wrapped or [Text()])
        return visual

    def _activity_text(self, width: int, body_height: int) -> tuple[Text, int]:
        visual = self._activity_visual_lines(width)
        max_scroll = max(0, len(visual) - body_height)
        self.scroll_offset = min(self.scroll_offset, max_scroll)
        start = max(0, len(visual) - body_height - self.scroll_offset)
        selected = visual[start : start + body_height]
        text = Text()
        if not selected:
            text.append("等待模型或工具活动…", style="dim")
        else:
            for index, line in enumerate(selected):
                if index:
                    text.append("\n")
                text.append_text(line)
        return text, len(visual)

    def _renderable(self) -> Layout:
        width, height = self._size()
        if self.console is not None:
            width = self.console.width
            height = self.console.height
        left_width = min(40, max(30, width // 4))
        activity_width = max(20, width - left_width - 1)
        activity_inner_width = max(10, activity_width - 7)
        body_height = max(1, height - 8)
        with self.lock:
            activity_text, visual_lines = self._activity_text(activity_inner_width, body_height)
            status_text = self._status_text()
            scroll_state = "follow tail" if self.scroll_offset == 0 else f"up {self.scroll_offset} lines"
        layout = Layout(name="root")
        layout.split_row(Layout(name="status", size=left_width), Layout(name="activity"))
        layout["status"].update(
            Panel(
                status_text,
                title="[bold bright_cyan] STATUS [/bold bright_cyan]",
                border_style="cyan",
                padding=(1, 2),
                expand=True,
            )
        )
        activity = Group(Text("RECENT ACTIVITY", style="bold bright_magenta"), activity_text)
        layout["activity"].update(
            Panel(
                activity,
                title="[bold bright_magenta] ACTIVITY [/bold bright_magenta]",
                subtitle=f"{visual_lines} wrapped lines · {scroll_state}",
                subtitle_align="right",
                border_style="magenta",
                padding=(1, 2),
                expand=True,
            )
        )
        return layout

    def render(self, *, refresh: bool = False, force: bool = False) -> None:
        if not self.active or self.live is None:
            return
        now = time.monotonic()
        if not force and now - self.last_render_at < 0.05:
            return
        self.live.update(self._renderable(), refresh=refresh)
        self.last_render_at = now

    def plain_recent(self, count: int) -> list[str]:
        with self.lock:
            source = list(self.lines)
            if self.current_line:
                source.append(self.current_line)
            return ["".join(value for value, _ in line) for line in source[-max(1, count):]]
