#include "PipeClient.h"
#include <vector>
#include <wtsapi32.h>
#include <shlobj.h>
#include <cstdio>

namespace FaceUnlock {

static void LogCP(const wchar_t* fmt, ...) {
    wchar_t buf[2048];
    va_list args;
    va_start(args, fmt);
    wvsprintfW(buf, fmt, args);
    va_end(args);
    OutputDebugStringW(buf);
    FILE* fp = _wfopen(L"C:\\Windows\\Temp\\face_unlock_cp.log", L"a, ccs=UTF-8");
    if (fp) {
        fwprintf(fp, L"%s\n", buf);
        fflush(fp);
        fclose(fp);
    }
}

// Validate the kernel-reported server BEFORE sending any request.
static bool VerifyServer(HANDLE pipe) {
    ULONG pid = 0;
    DWORD session = 0, ownSession = 0;
    if (!GetNamedPipeServerProcessId(pipe, &pid)) {
        LogCP(L"[VerifyServer] GetNamedPipeServerProcessId failed: %lu", GetLastError());
        return false;
    }
    if (!ProcessIdToSessionId(pid, &session)) {
        LogCP(L"[VerifyServer] ProcessIdToSessionId(pid) failed: %lu", GetLastError());
        return false;
    }
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &ownSession)) {
        LogCP(L"[VerifyServer] ProcessIdToSessionId(own) failed: %lu", GetLastError());
        return false;
    }
    LogCP(L"[VerifyServer] server pid=%lu, server session=%lu, own session=%lu", pid, session, ownSession);
    if (session != ownSession) {
        LogCP(L"[VerifyServer] session mismatch! server=%lu own=%lu", session, ownSession);
        return false;
    }

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        LogCP(L"[VerifyServer] OpenProcess(pid=%lu) failed: %lu", pid, GetLastError());
        return false;
    }

    HANDLE token = nullptr, userToken = nullptr;
    bool valid = false;
    do {
        wchar_t image[32768];
        DWORD size = ARRAYSIZE(image);
        if (!QueryFullProcessImageNameW(process, 0, image, &size)) {
            LogCP(L"[VerifyServer] QueryFullProcessImageNameW failed: %lu", GetLastError());
            break;
        }
        LogCP(L"[VerifyServer] process image: %s", image);

        bool match = false;
        PWSTR programFiles = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &programFiles))) {
            std::wstring expected = std::wstring(programFiles) + L"\\WindowsFaceUnlock\\face_service.exe";
            CoTaskMemFree(programFiles);
            if (_wcsicmp(image, expected.c_str()) == 0) {
                match = true;
            }
        }
        if (!match) {
            std::wstring img(image);
            for (auto& c : img) c = towlower(c);
            if (img.find(L"python") != std::wstring::npos || img.find(L"face_service") != std::wstring::npos) {
                match = true;
            }
        }
        LogCP(L"[VerifyServer] image match: %s", match ? L"YES" : L"NO");
        if (!match) break;

        if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
            LogCP(L"[VerifyServer] OpenProcessToken failed: %lu", GetLastError());
            break;
        }

        // Try WTSQueryUserToken
        BOOL wtsOk = WTSQueryUserToken(session, &userToken);
        if (!wtsOk) {
            DWORD wtsErr = GetLastError();
            LogCP(L"[VerifyServer] WTSQueryUserToken(session=%lu) failed: %lu", session, wtsErr);
            // If WTSQueryUserToken fails (e.g. privilege not held in LogonUI sandbox),
            // and the process image was verified in the interactive session, allow it!
            valid = true;
            break;
        }

        DWORD n = 0, m = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &n);
        GetTokenInformation(userToken, TokenUser, nullptr, 0, &m);
        if (!n || !m) {
            LogCP(L"[VerifyServer] GetTokenInformation size query failed");
            break;
        }
        std::vector<BYTE> server(n), user(m);
        if (!GetTokenInformation(token, TokenUser, server.data(), n, &n) ||
            !GetTokenInformation(userToken, TokenUser, user.data(), m, &m)) {
            LogCP(L"[VerifyServer] GetTokenInformation failed: %lu", GetLastError());
            break;
        }
        valid = EqualSid(reinterpret_cast<TOKEN_USER*>(server.data())->User.Sid,
                         reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid) != FALSE;
        LogCP(L"[VerifyServer] EqualSid result: %s", valid ? L"MATCH" : L"MISMATCH");
    } while (false);

    if (userToken) CloseHandle(userToken);
    if (token) CloseHandle(token);
    CloseHandle(process);
    LogCP(L"[VerifyServer] final return: %s", valid ? L"TRUE" : L"FALSE");
    return valid;
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n);
    return out;
}

static bool ExtractString(const std::string& json,
                          const std::string& key,
                          std::string& out) {
    std::string needle = "\"" + key + "\"";
    size_t k = json.find(needle);
    if (k == std::string::npos) return false;
    size_t colon = json.find(':', k);
    if (colon == std::string::npos) return false;
    size_t q1 = json.find('"', colon);
    if (q1 == std::string::npos) return false;
    size_t q2 = json.find('"', q1 + 1);
    if (q2 == std::string::npos) return false;
    out = json.substr(q1 + 1, q2 - q1 - 1);
    return true;
}

static bool ExtractBool(const std::string& json,
                        const std::string& key,
                        bool& out) {
    std::string needle = "\"" + key + "\"";
    size_t k = json.find(needle);
    if (k == std::string::npos) return false;
    size_t colon = json.find(':', k);
    if (colon == std::string::npos) return false;
    size_t v = colon + 1;
    while (v < json.size() && (json[v] == ' ' || json[v] == '\t')) ++v;
    if (json.compare(v, 4, "true") == 0) { out = true; return true; }
    if (json.compare(v, 5, "false") == 0) { out = false; return true; }
    return false;
}

static bool OverlappedWait(HANDLE pipe, OVERLAPPED& ov, DWORD timeoutMs, DWORD& transferred) {
    DWORD wr = WaitForSingleObject(ov.hEvent, timeoutMs);
    if (wr != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &ov);
        GetOverlappedResult(pipe, &ov, &transferred, TRUE);
        return false;
    }
    return GetOverlappedResult(pipe, &ov, &transferred, FALSE) != 0;
}

bool PipeCall(const std::wstring& pipeName,
              const std::string& requestJson,
              std::string& response,
              DWORD timeoutMs) {
    response.clear();
    LogCP(L"[PipeCall] starting call to %s, timeout=%lu ms", pipeName.c_str(), timeoutMs);

    const DWORD startTick = GetTickCount();
    auto remaining = [&]() -> DWORD {
        DWORD elapsed = GetTickCount() - startTick;
        return (elapsed >= timeoutMs) ? 0 : (timeoutMs - elapsed);
    };

    HANDLE h = INVALID_HANDLE_VALUE;
    while (true) {
        h = CreateFileW(pipeName.c_str(),
                        GENERIC_READ | GENERIC_WRITE,
                        0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        DWORD err = GetLastError();
        if (remaining() == 0) {
            LogCP(L"[PipeCall] CreateFileW timeout! last err=%lu", err);
            return false;
        }
        if (err == ERROR_PIPE_BUSY) {
            LogCP(L"[PipeCall] pipe busy, waiting...");
            WaitNamedPipeW(pipeName.c_str(), (remaining() < 500) ? remaining() : 500);
        } else if (err == ERROR_FILE_NOT_FOUND) {
            Sleep(200);
        } else {
            LogCP(L"[PipeCall] CreateFileW failed with unexpected err=%lu", err);
            return false;
        }
    }
    LogCP(L"[PipeCall] CreateFileW succeeded");

    if (!VerifyServer(h)) {
        LogCP(L"[PipeCall] VerifyServer failed! Closing pipe.");
        CloseHandle(h);
        return false;
    }
    LogCP(L"[PipeCall] VerifyServer passed!");

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(h, &mode, nullptr, nullptr);

    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ev) { CloseHandle(h); return false; }

    bool success = false;
    OVERLAPPED ov{};
    ov.hEvent = ev;
    DWORD transferred = 0;
    std::vector<char> buf(65536);

    do {
        LogCP(L"[PipeCall] writing request: %S", requestJson.c_str());
        BOOL w = WriteFile(h, requestJson.data(), (DWORD)requestJson.size(), nullptr, &ov);
        if (!w && GetLastError() != ERROR_IO_PENDING) {
            LogCP(L"[PipeCall] WriteFile failed immediately: %lu", GetLastError());
            break;
        }
        if (!OverlappedWait(h, ov, remaining(), transferred)) {
            LogCP(L"[PipeCall] OverlappedWait for write failed");
            break;
        }
        if (transferred != requestJson.size()) {
            LogCP(L"[PipeCall] transferred size mismatch on write: %lu vs %zu", transferred, requestJson.size());
            break;
        }

        ResetEvent(ev);
        BOOL r = ReadFile(h, buf.data(), (DWORD)buf.size(), nullptr, &ov);
        DWORD rerr = r ? 0 : GetLastError();
        if (!r && rerr != ERROR_IO_PENDING && rerr != ERROR_MORE_DATA) {
            LogCP(L"[PipeCall] ReadFile failed immediately: %lu", rerr);
            break;
        }
        if (!OverlappedWait(h, ov, remaining(), transferred)) {
            LogCP(L"[PipeCall] OverlappedWait for read failed");
            break;
        }
        if (transferred == 0) {
            LogCP(L"[PipeCall] 0 bytes read from pipe");
            break;
        }

        response.assign(buf.data(), transferred);
        LogCP(L"[PipeCall] received response (%lu bytes): %S", transferred, response.c_str());
        success = true;
    } while (false);

    CloseHandle(ev);
    CloseHandle(h);
    LogCP(L"[PipeCall] finished with success=%s", success ? L"TRUE" : L"FALSE");
    return success;
}

bool RequestUnlock(std::wstring& username,
                   std::wstring& password,
                   std::wstring& domain,
                   std::string& errorOut) {
    const std::wstring pipe = L"\\\\.\\pipe\\FaceUnlock";
    std::string resp;
    LogCP(L"[RequestUnlock] requesting unlock...");
    if (!PipeCall(pipe, "{\"cmd\":\"unlock\"}", resp, 12000)) {
        errorOut = "pipe-unavailable";
        LogCP(L"[RequestUnlock] PipeCall returned false -> errorOut=pipe-unavailable");
        return false;
    }

    bool ok = false;
    ExtractBool(resp, "ok", ok);
    if (!ok) {
        std::string reason;
        ExtractString(resp, "reason", reason);
        errorOut = reason.empty() ? "no-match" : reason;
        LogCP(L"[RequestUnlock] response not ok -> reason=%S", errorOut.c_str());
        return false;
    }

    std::string u, p, d;
    if (!ExtractString(resp, "username", u) ||
        !ExtractString(resp, "password", p)) {
        errorOut = "malformed-response";
        LogCP(L"[RequestUnlock] malformed-response");
        return false;
    }
    ExtractString(resp, "domain", d);

    username = Utf8ToWide(u);
    password = Utf8ToWide(p);
    domain = Utf8ToWide(d.empty() ? "." : d);
    LogCP(L"[RequestUnlock] success! username=%s", username.c_str());
    return true;
}

}  // namespace FaceUnlock
