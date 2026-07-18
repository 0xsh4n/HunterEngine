"""
Scan control — pause / resume / quit during a running pipeline.

Ctrl+C (SIGINT) pauses the scan and prompts:
  [r] Resume   — continue from the current phase boundary
  [q] Quit     — save checkpoint and exit cleanly
  [a] Abort    — exit without saving

Between phases the orchestrator also checkpoints automatically so
``python main.py scan --resume`` can continue later.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
import threading
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger("hunterengine.scan_control")


class ControlAction(str, Enum):
    CONTINUE = "continue"
    PAUSE = "pause"
    QUIT = "quit"       # save + exit
    ABORT = "abort"     # exit without save


class ScanController:
    """
    Cooperative pause/quit controller for the scan pipeline.

    Long-running phases should call ``await controller.checkpoint()``
    at safe boundaries; the orchestrator does this between phases.
    """

    def __init__(self, interactive: bool = True) -> None:
        self.interactive = interactive
        self._paused = threading.Event()
        self._quit = threading.Event()
        self._abort = threading.Event()
        self._interrupt_count = 0
        self._lock = threading.Lock()
        self._prompt_active = False
        self._installed = False
        self._prev_handler: Any = None
        self.on_pause: Optional[Callable[[], None]] = None

    @property
    def should_quit(self) -> bool:
        return self._quit.is_set()

    @property
    def should_abort(self) -> bool:
        return self._abort.is_set()

    @property
    def should_stop(self) -> bool:
        return self.should_quit or self.should_abort

    @property
    def is_paused(self) -> bool:
        return self._paused.is_set()

    def install(self) -> None:
        """Install SIGINT handler (idempotent)."""
        if self._installed:
            return
        try:
            self._prev_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, self._on_sigint)
            self._installed = True
            logger.debug("ScanController SIGINT handler installed")
        except (ValueError, OSError) as exc:
            logger.debug("Could not install SIGINT handler: %s", exc)

    def uninstall(self) -> None:
        if not self._installed:
            return
        try:
            if self._prev_handler is not None:
                signal.signal(signal.SIGINT, self._prev_handler)
        except (ValueError, OSError):
            pass
        self._installed = False

    def _on_sigint(self, signum: int, frame: Any) -> None:
        with self._lock:
            self._interrupt_count += 1
            count = self._interrupt_count

        if count >= 2 and self._paused.is_set():
            sys.stderr.write("\n[!] Aborting without save (second Ctrl+C).\n")
            self._abort.set()
            self._paused.clear()
            return

        if self._prompt_active:
            sys.stderr.write("\n[!] Aborting.\n")
            self._abort.set()
            self._paused.clear()
            return

        sys.stderr.write(
            "\n\n[!] Scan interrupted — pausing at next safe boundary.\n"
            "    Press Ctrl+C again to abort without saving.\n\n"
        )
        self._paused.set()
        if self.on_pause:
            try:
                self.on_pause()
            except Exception:
                pass

    async def checkpoint(self, label: str = "") -> ControlAction:
        """
        Call at safe points (between phases).

        If paused, shows interactive menu and waits for user choice.
        Returns the action to take.
        """
        if self.should_abort:
            return ControlAction.ABORT
        if self.should_quit:
            return ControlAction.QUIT
        if not self.is_paused:
            return ControlAction.CONTINUE

        where = f" ({label})" if label else ""
        logger.info("Scan paused%s — waiting for user action", where)
        return await asyncio.to_thread(self._prompt_user, label)

    def _prompt_user(self, label: str = "") -> ControlAction:
        self._prompt_active = True
        try:
            where = f" after {label}" if label else ""
            print(
                f"\n{'═' * 56}\n"
                f"  HunterEngine paused{where}\n"
                f"{'═' * 56}\n"
                f"  [r] Resume  — continue scanning\n"
                f"  [q] Quit    — save checkpoint and exit\n"
                f"  [a] Abort   — exit without saving\n"
                f"{'═' * 56}",
                flush=True,
            )
            if not self.interactive or not sys.stdin.isatty():
                print("  (non-interactive) defaulting to Quit + save", flush=True)
                self._quit.set()
                self._paused.clear()
                return ControlAction.QUIT

            while True:
                try:
                    choice = input("  Choice [r/q/a]: ").strip().lower()
                except EOFError:
                    choice = "q"
                except KeyboardInterrupt:
                    print("\n  Aborting.", flush=True)
                    self._abort.set()
                    self._paused.clear()
                    return ControlAction.ABORT

                if choice in ("r", "resume", ""):
                    print("  Resuming…\n", flush=True)
                    with self._lock:
                        self._interrupt_count = 0
                    self._paused.clear()
                    return ControlAction.CONTINUE
                if choice in ("q", "quit"):
                    print("  Saving checkpoint and quitting…\n", flush=True)
                    self._quit.set()
                    self._paused.clear()
                    return ControlAction.QUIT
                if choice in ("a", "abort"):
                    print("  Aborting without save…\n", flush=True)
                    self._abort.set()
                    self._paused.clear()
                    return ControlAction.ABORT
                print("  Enter r, q, or a.", flush=True)
        finally:
            self._prompt_active = False

    def request_quit(self) -> None:
        self._quit.set()
        self._paused.clear()

    def request_abort(self) -> None:
        self._abort.set()
        self._paused.clear()

    def clear(self) -> None:
        self._paused.clear()
        self._quit.clear()
        self._abort.clear()
        with self._lock:
            self._interrupt_count = 0
