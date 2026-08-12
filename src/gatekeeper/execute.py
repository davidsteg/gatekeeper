"""Prozessausfuehrung (REQUIREMENTS.md §8).

Kein Shell-Interpreter, harte Zeitlimits, begrenzte Ausgabe, Serialisierung
pro Ressource. Die Ausfuehrung selbst ist der kleinste Teil -- der Aufwand
steckt darin, dass sie sich bei Zeitueberschreitung ehrlich verhaelt.
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import signal
import sys
import time

from .errors import Denied, DenialReason

#: Ergebnis-Zustaende. `unknown` ist der wichtige: bei einem Zeitlimit ist
#: nicht entschieden, ob die Operation drueben gelaufen ist (FR-6.9).
OUTCOME_OK = "ok"
OUTCOME_FAILED = "failed"
OUTCOME_UNKNOWN = "unknown"


@dataclasses.dataclass(slots=True)
class Result:
    outcome: str
    exit_code: int | None
    stdout: str
    stderr: str
    truncated: bool
    duration_ms: int


class ResourceLocks:
    """Serialisiert Aufrufe je Ressource (FR-6.7).

    Zwei gleichzeitige `compose up -d` auf denselben Stack duerfen sich nicht
    ueberlappen -- der zweite sieht sonst einen halb gestarteten Zustand.
    """

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}

    def get(self, key: str) -> asyncio.Lock:
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock


async def _read_capped(
    stream: asyncio.StreamReader | None, limit: int
) -> tuple[bytes, bool]:
    """Liest bis `limit` Bytes und meldet, ob abgeschnitten wurde."""
    if stream is None:
        return b"", False
    chunks: list[bytes] = []
    total = 0
    truncated = False
    while True:
        chunk = await stream.read(8192)
        if not chunk:
            break
        if total + len(chunk) > limit:
            chunks.append(chunk[: limit - total])
            truncated = True
            # Weiterlesen und verwerfen, damit der Prozess nicht auf einer
            # vollen Pipe blockiert und ins Zeitlimit laeuft.
            while await stream.read(65536):
                pass
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks), truncated


def _terminate(process: asyncio.subprocess.Process) -> None:
    """Beendet den Prozess samt Kindern.

    `docker compose` startet Unterprozesse; ein `kill` auf den Elternprozess
    allein liesse sie zurueck. Unter POSIX laeuft der Aufruf deshalb in einer
    eigenen Sitzung, die als Ganzes beendet wird.
    """
    if process.returncode is not None:
        return
    if sys.platform != "win32":
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            return
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        process.kill()
    except ProcessLookupError:
        pass


async def run(
    argv: list[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int,
    idempotent: bool,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> Result:
    """Fuehrt `argv` ohne Shell aus.

    Bei Zeitueberschreitung wird der Prozessbaum beendet. Das Ergebnis ist dann
    `unknown` statt `failed`, sofern die Operation nicht idempotent ist: ein als
    Fehler gemeldetes Zeitlimit provoziert genau die Wiederholung, die bei einem
    bereits durchgelaufenen Schreibzugriff das Duplikat erzeugt (FR-6.9).
    """
    started = time.monotonic()
    popen_kwargs: dict[str, object] = {}
    if sys.platform != "win32":
        popen_kwargs["start_new_session"] = True

    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
            cwd=cwd,
            env=env,
            **popen_kwargs,  # type: ignore[arg-type]
        )
    except FileNotFoundError as exc:
        raise Denied(
            DenialReason.EXECUTOR_UNAVAILABLE,
            f"Executable not found: {argv[0]}",
        ) from exc
    except PermissionError as exc:
        raise Denied(
            DenialReason.EXECUTOR_UNAVAILABLE,
            f"No permission to execute {argv[0]}",
        ) from exc

    try:
        stdout_bytes, out_truncated, stderr_bytes, err_truncated = await asyncio.wait_for(
            _gather(process, max_output_bytes), timeout=timeout_seconds
        )
    except (asyncio.TimeoutError, TimeoutError):
        _terminate(process)
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except (asyncio.TimeoutError, TimeoutError):
            pass
        duration = int((time.monotonic() - started) * 1000)
        return Result(
            outcome=OUTCOME_FAILED if idempotent else OUTCOME_UNKNOWN,
            exit_code=None,
            stdout="",
            stderr=(
                f"Timeout of {timeout_seconds}s exceeded, process killed."
                if idempotent
                else (
                    f"Timeout of {timeout_seconds}s exceeded, process killed. "
                    "The outcome is UNKNOWN: the operation may have completed. "
                    "Do not retry without checking the state first."
                )
            ),
            truncated=False,
            duration_ms=duration,
        )

    await process.wait()
    duration = int((time.monotonic() - started) * 1000)
    return Result(
        outcome=OUTCOME_OK if process.returncode == 0 else OUTCOME_FAILED,
        exit_code=process.returncode,
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
        truncated=out_truncated or err_truncated,
        duration_ms=duration,
    )


async def _gather(
    process: asyncio.subprocess.Process, limit: int
) -> tuple[bytes, bool, bytes, bool]:
    (out, out_trunc), (err, err_trunc) = await asyncio.gather(
        _read_capped(process.stdout, limit),
        _read_capped(process.stderr, limit),
    )
    return out, out_trunc, err, err_trunc
