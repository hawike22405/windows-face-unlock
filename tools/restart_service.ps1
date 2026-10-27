Stop-ScheduledTask -TaskName 'FaceUnlock-Service' -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName 'FaceUnlock-Presence' -ErrorAction SilentlyContinue

Get-Process python, pythonw -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        if ($_.Path -like '*face-unlock*' -or ($_.CommandLine -and $_.CommandLine -like '*face_service*')) {
            Write-Host "Killing PID $($_.Id)"
            Stop-Process -Id $_.Id -Force
        }
    } catch {}
}

# Also kill by command line (WMI)
Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*face_service*' -or $_.CommandLine -like '*presence_monitor*' } |
    ForEach-Object { Write-Host "WMI Kill PID $($_.ProcessId)"; Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

Start-Sleep 2
Start-ScheduledTask -TaskName 'FaceUnlock-Service'
$presence = Get-ScheduledTask -TaskName 'FaceUnlock-Presence' -ErrorAction SilentlyContinue
if ($presence -and $presence.State -ne 'Disabled') {
    Start-ScheduledTask -TaskName 'FaceUnlock-Presence' -ErrorAction SilentlyContinue
}
Write-Host "Done."
