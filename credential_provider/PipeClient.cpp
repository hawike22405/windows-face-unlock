#include "PipeClient.h"
#include <vector>
#include <wtsapi32.h>
#include <shlobj.h>

namespace FaceUnlock {

// Validate the kernel-reported server BEFORE sending any request. An ordinary
// user cannot substitute an executable in this administrator-owned directory.
static bool VerifyServer(HANDLE pipe) {
    ULONG pid = 0;
    DWORD session = 0, ownSession = 0;
    if (!GetNamedPipeServerProcessId(pipe, &pid) ||
        !ProcessIdToSessionId(pid, &session) ||
        !ProcessIdToSessionId(GetCurrentProcessId(), &ownSession) ||
        session != ownSession) return false;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return false;
    HANDLE token = nullptr, userToken = nullptr;
    bool valid = false;
    do {
        wchar_t image[32768];
        DWORD size = ARRAYSIZE(image);
        if (!QueryFullProcessImageNameW(process, 0, image, &size)) break;
        PWSTR programFiles = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &programFiles))) break;
        std::wstring expected = std::wstring(programFiles) + L"\\WindowsFaceUnlock\\face_service.exe";
        CoTaskMemFree(programFiles);
        if (_wcsicmp(image, expected.c_str()) != 0) break;
        if (!OpenProcessToken(process, TOKEN_QUERY, &token) ||
            !WTSQueryUserToken(session, &userToken)) break;
        DWORD n = 0, m = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &n);
        GetTokenInformation(userToken, TokenUser, nullptr, 0, &m);
        if (!n || !m) break;
        std::vector<BYTE> server(n), user(m);
        if (!GetTokenInformation(token, TokenUser, server.data(), n, &n) ||
            !GetTokenInformation(userToken, TokenUser, user.data(), m, &m)) break;
        valid = EqualSid(reinterpret_cast<TOKEN_USER*>(server.data())->User.Sid,
                         reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid) != FALSE;
    } while (false);
    if (userToken) CloseHandle(userToken);
    if (token) CloseHandle(token);
    CloseHandle(process);
    return valid;
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n);
    return out;
}

// Extract a top-level JSON string value for `key`. Naive: assumes no nested
// braces / no embedded quotes in the value. Enough for our tiny protocol.
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
    // skip whitespace
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
        // drain any pending completion so CloseHandle is safe
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
    // Total deadline for the whole transaction.
    const DWORD startTick = GetTickCount();
    auto remaining = [&]() -> DWORD {
        DWORD elapsed = GetTickCount() - startTick;
        return (elapsed >= timeoutMs) ? 0 : (timeoutMs - elapsed);
    };

    // Try to open the pipe within the total timeout.
    HANDLE h = INVALID_HANDLE_VALUE;
    while (true) {
        h = CreateFileW(pipeName.c_str(),
                        FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                        0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        DWORD err = GetLastError();
        if (remaining() == 0) return false;
        if (err == ERROR_PIPE_BUSY) {
            WaitNamedPipeW(pipeName.c_str(), (remaining() < 500) ? remaining() : 500);
        } else if (err == ERROR_FILE_NOT_FOUND) {
            // Service not running; short sleep and retry within budget.
            Sleep(200);
        } else {
            return false;
        }
    }

    if (!VerifyServer(h)) { CloseHandle(h); return false; }

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
        BOOL w = WriteFile(h, requestJson.data(), (DWORD)requestJson.size(), nullptr, &ov);
        if (!w && GetLastError() != ERROR_IO_PENDING) break;
        if (!OverlappedWait(h, ov, remaining(), transferred)) break;
        if (transferred != requestJson.size()) break;

        ResetEvent(ev);
        BOOL r = ReadFile(h, buf.data(), (DWORD)buf.size(), nullptr, &ov);
        DWORD rerr = r ? 0 : GetLastError();
        if (!r && rerr != ERROR_IO_PENDING && rerr != ERROR_MORE_DATA) break;
        if (!OverlappedWait(h, ov, remaining(), transferred)) break;
        if (transferred == 0) break;

        response.assign(buf.data(), transferred);
        success = true;
    } while (false);

    CloseHandle(ev);
    CloseHandle(h);
    return success;
}

bool RequestUnlock(std::wstring& username,
                   std::wstring& password,
                   std::wstring& domain,
                   std::string& errorOut) {
    const std::wstring pipe = L"\\\\.\\pipe\\FaceUnlock";
    std::string resp;
    // 12s total: if the service is dead or the user is not visible, fail fast
    // so the user can switch to the password tile without feeling stuck.
    if (!PipeCall(pipe, "{\"cmd\":\"unlock\"}", resp, 12000)) {
        errorOut = "pipe-unavailable";
        return false;
    }

    bool ok = false;
    ExtractBool(resp, "ok", ok);
    if (!ok) {
        std::string reason;
        ExtractString(resp, "reason", reason);
        errorOut = reason.empty() ? "no-match" : reason;
        return false;
    }

    std::string u, p, d;
    if (!ExtractString(resp, "username", u) ||
        !ExtractString(resp, "password", p)) {
        errorOut = "malformed-response";
        return false;
    }
    ExtractString(resp, "domain", d);

    username = Utf8ToWide(u);
    password = Utf8ToWide(p);
    domain = Utf8ToWide(d.empty() ? "." : d);
    return true;
}

}  // namespace FaceUnlock
