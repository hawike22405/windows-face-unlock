"""Windows pipe authorization. Request JSON is never an identity source."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import ntpath

import win32api
import win32con
import win32pipe
import win32security

SYSTEM_SID = "S-1-5-18"
# Client read/write rights, deliberately excluding FILE_CREATE_PIPE_INSTANCE (4).
PIPE_CLIENT_ACCESS = 0x00100103
PIPE_REJECT_REMOTE_CLIENTS = 0x8
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000


def current_user_sid() -> str:
    with win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY) as token:
        return win32security.ConvertSidToStringSid(
            win32security.GetTokenInformation(token, win32security.TokenUser)[0])


def build_pipe_security():
    owner = win32security.ConvertStringSidToSid(current_user_sid())
    system = win32security.ConvertStringSidToSid(SYSTEM_SID)
    acl = win32security.ACL()
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, owner)
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, PIPE_CLIENT_ACCESS, system)
    sd = win32security.SECURITY_DESCRIPTOR()
    sd.SetSecurityDescriptorDacl(True, acl, False)
    sa = win32security.SECURITY_ATTRIBUTES()
    sa.SECURITY_DESCRIPTOR = sd
    sa.bInheritHandle = False
    return sa


def _client_process_id(handle) -> int:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.GetNamedPipeClientProcessId
    query.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    query.restype = wintypes.BOOL
    pid = wintypes.ULONG()
    if not query(int(handle), ctypes.byref(pid)):
        raise ctypes.WinError(ctypes.get_last_error())
    return pid.value


def _process_image(pid: int) -> str:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.QueryFullProcessImageNameW
    query.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                      ctypes.POINTER(wintypes.DWORD)]
    query.restype = wintypes.BOOL
    with win32api.OpenProcess(0x1000, False, pid) as process:
        path = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(path))
        if not query(int(process), 0, path, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return path.value


def client_role(handle) -> str | None:
    """Called AFTER ReadFile: token is tied to the message just received.

    The CP connects with SECURITY_IDENTIFICATION, so the service can inspect
    SYSTEM's identity without being permitted to act as SYSTEM.
    Any lookup/impersonation failure denies the request.
    """
    try:
        owner = current_user_sid()
        win32pipe.ImpersonateNamedPipeClient(handle)
        try:
            with win32security.OpenThreadToken(win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True) as token:
                sid = win32security.ConvertSidToStringSid(
                    win32security.GetTokenInformation(token, win32security.TokenUser)[0])
                session = win32security.GetTokenInformation(token, win32security.TokenSessionId)
        finally:
            win32security.RevertToSelf()
        if sid == owner and sid != SYSTEM_SID:
            return "user"
        if sid != SYSTEM_SID:
            return None
        # SYSTEM alone is insufficient: require the real Windows LogonUI in
        # the same interactive session as this per-user service.
        with win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY) as token:
            own_session = win32security.GetTokenInformation(token, win32security.TokenSessionId)
        expected = ntpath.join(win32api.GetSystemDirectory(), "LogonUI.exe")
        if session == own_session and ntpath.normcase(_process_image(_client_process_id(handle))) == ntpath.normcase(expected):
            return "credential_provider"
    except Exception:
        return None
    return None


def command_allowed(cmd: str, role: str | None) -> bool:
    if cmd == "unlock":
        return role == "credential_provider"
    return role == "user"
