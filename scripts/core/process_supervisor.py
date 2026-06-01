#!/usr/bin/env python3
"""Cross-platform subprocess supervisor for GUI-launched local services."""
from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path
from typing import Any, Iterable


def _hidden_windows_kwargs() -> dict[str, object]:
    if os.name != "nt":
        return {}
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0
    return {"creationflags": flags, "startupinfo": startupinfo}


class ProcessSupervisor:
    """Manage one child process with OS-level containment where available."""

    def __init__(
        self,
        binary_path: Path,
        arguments: Iterable[str],
        workspace_root: Path,
        *,
        hidden_window: bool = True,
    ) -> None:
        self.binary_path = binary_path
        self.arguments = list(arguments)
        self.workspace_root = workspace_root
        self.hidden_window = hidden_window
        self.process: subprocess.Popen[str] | None = None
        self._job_handle: Any | None = None

    @property
    def pid(self) -> int | None:
        return self.process.pid if self.process else None

    @property
    def stdout(self) -> Any | None:
        return self.process.stdout if self.process else None

    def poll(self) -> int | None:
        return self.process.poll() if self.process else None

    def spawn(self) -> subprocess.Popen[str]:
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Missing executable: {self.binary_path}")
        if self.process and self.process.poll() is None:
            return self.process

        cmd = [str(self.binary_path), *self.arguments]
        if os.name == "nt":
            self.process = self._spawn_windows_job(cmd)
        else:
            self.process = self._spawn_posix_group(cmd)
        return self.process

    def _spawn_posix_group(self, cmd: list[str]) -> subprocess.Popen[str]:
        return subprocess.Popen(
            cmd,
            cwd=str(self.workspace_root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def _spawn_windows_job(self, cmd: list[str]) -> subprocess.Popen[str]:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class JobBasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class JobExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JobBasicLimitInformation),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise ctypes.WinError(ctypes.get_last_error())

        job_object_extended_limit_information = 9
        job_object_limit_kill_on_job_close = 0x00002000
        info = JobExtendedLimitInformation()
        info.BasicLimitInformation.LimitFlags = job_object_limit_kill_on_job_close
        ok = kernel32.SetInformationJobObject(
            job,
            job_object_extended_limit_information,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            err = ctypes.get_last_error()
            kernel32.CloseHandle(job)
            raise ctypes.WinError(err)

        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        if self.hidden_window:
            flags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)

        proc = subprocess.Popen(
            cmd,
            cwd=str(self.workspace_root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )
        ok = kernel32.AssignProcessToJobObject(job, int(proc._handle))  # noqa: SLF001
        if not ok:
            err = ctypes.get_last_error()
            try:
                proc.kill()
                proc.wait(timeout=5)
            finally:
                kernel32.CloseHandle(job)
            raise ctypes.WinError(err)
        self._job_handle = job
        return proc

    def terminate(self, timeout: float = 5.0) -> None:
        proc = self.process
        if proc is None:
            self._close_job_handle()
            return

        if proc.poll() is None:
            if os.name == "nt":
                self._terminate_windows_job()
            else:
                self._terminate_posix_group(timeout)
        self._close_job_handle()
        self.process = None

    def _terminate_posix_group(self, timeout: float) -> None:
        import signal

        assert self.process is not None
        try:
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            self.process.wait(timeout=timeout)
        except Exception:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
            except Exception:
                self.process.kill()
            self.process.wait(timeout=timeout)

    def _terminate_windows_job(self) -> None:
        if self._job_handle:
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.TerminateJobObject(self._job_handle, 1)
        elif self.process and self.process.poll() is None:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(self.process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                **_hidden_windows_kwargs(),
            )

    def _close_job_handle(self) -> None:
        if not self._job_handle or platform.system().lower() != "windows":
            self._job_handle = None
            return
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle(self._job_handle)
        self._job_handle = None
