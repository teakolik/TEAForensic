"""
TEA Forensic Collector - Windows Artifact Collection Engine
Author: TEA Security
Platform: Windows (requires Admin/SYSTEM privileges)
"""

import os
import re
import sys
import json
import time
import ctypes
import hashlib
import platform
import datetime
import subprocess
import urllib.request
import urllib.error

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import winreg


def run_cmd(cmd, shell=True, timeout=30):
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True,
            timeout=timeout, encoding='utf-8', errors='replace'
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command exceeded {timeout}s: {cmd}"
    except Exception as e:
        return f"[ERROR] {str(e)}"


def run_powershell(script, timeout=60):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=timeout, encoding='utf-8', errors='replace'
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] PowerShell script exceeded {timeout}s"
    except Exception as e:
        return f"[ERROR] {str(e)}"


# ─────────────────────────────────────────────
# 1. SYSTEM INFO
# ─────────────────────────────────────────────
def collect_system_info():
    info = {}
    info['hostname']       = run_cmd("hostname")
    info['username']       = os.environ.get("USERNAME", "N/A")
    info['domain']         = os.environ.get("USERDOMAIN", "N/A")
    info['os']             = run_cmd("ver")
    info['architecture']   = platform.architecture()[0]
    info['uptime']         = run_cmd('net statistics workstation | findstr /C:"Statistics since"')
    info['timezone']       = run_cmd("tzutil /g")
    info['collection_time']= datetime.datetime.now().isoformat()
    info['collector_user'] = os.environ.get("USERNAME", "N/A")
    info['is_admin']       = bool(ctypes.windll.shell32.IsUserAnAdmin()) if IS_WINDOWS else False
    info['ip_config']      = run_cmd("ipconfig /all")
    # dns_cache collect_network() içinde toplanıyor
    info['os_version']     = run_powershell(
        "(Get-WmiObject Win32_OperatingSystem) | Select-Object Caption,Version,BuildNumber,OSArchitecture | ConvertTo-Json"
    )
    return info


# ─────────────────────────────────────────────
# 2. PROCESS LIST
# ─────────────────────────────────────────────
def collect_processes():
    raw = run_powershell("""\
$wmiProcs = Get-WmiObject Win32_Process
$wmiMap = @{}
foreach ($w in $wmiProcs) { $wmiMap[$w.ProcessId] = $w }
Get-Process | ForEach-Object {
    $wmi = $wmiMap[$_.Id]
    $hash = 'N/A'
    if ($_.Path -and (Test-Path $_.Path)) {
        try { $hash = (Get-FileHash $_.Path -Algorithm SHA256 -ErrorAction Stop).Hash }
        catch { $hash = 'HASH_ERROR' }
    }
    [PSCustomObject]@{
        PID         = $_.Id
        PPID        = if ($wmi) { $wmi.ParentProcessId } else { $null }
        ProcessName = $_.ProcessName
        CPU         = [math]::Round($_.CPU, 2)
        RAM_MB      = [math]::Round($_.WorkingSet / 1MB, 2)
        StartTime   = $_.StartTime
        Path        = $_.Path
        CommandLine = if ($wmi) { $wmi.CommandLine } else { $null }
        Hash        = $hash
    }
} | ConvertTo-Json -Depth 3
""", timeout=120)
    return {"processes": raw, "tasklist_verbose": run_cmd("tasklist /v /fo csv")}


# ─────────────────────────────────────────────
# 3. NETWORK
# ─────────────────────────────────────────────
def collect_network():
    return {
        "netstat":               run_cmd("netstat -anob", timeout=30),
        "routing_table":         run_cmd("route print"),
        "arp_cache":             run_cmd("arp -a"),
        "dns_cache":             run_cmd("ipconfig /displaydns"),
        "shares":                run_cmd("net share"),
        "listening_ports":       run_powershell("""\
Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} |
Select-Object LocalAddress, LocalPort, State,
@{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}},
@{N='PID';E={$_.OwningProcess}} | ConvertTo-Json
"""),
        "established_connections": run_powershell("""\
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
@{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}},
@{N='PID';E={$_.OwningProcess}} | ConvertTo-Json
"""),
        "wifi_profiles":         run_cmd("netsh wlan show profiles"),
        "firewall_rules_allow":  run_powershell("""\
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Action -eq 'Allow'} |
Select-Object DisplayName, Direction, Action, Profile |
Sort-Object Direction | ConvertTo-Json -Depth 2
""", timeout=60),
    }


# ─────────────────────────────────────────────
# 4. REGISTRY
# ─────────────────────────────────────────────
def read_reg_key(hive, path, enumerate_subkeys=False):
    results = []
    try:
        key = winreg.OpenKey(hive, path)
    except Exception as e:
        results.append({"error": str(e), "path": path})
        return results

    try:
        i = 0
        while True:
            try:
                name, data, reg_type = winreg.EnumValue(key, i)
                results.append({"name": name, "data": str(data), "type": reg_type})
                i += 1
            except OSError:
                break

        if enumerate_subkeys:
            j = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, j)
                    subkey_path = path + "\\" + subkey_name
                    subkey_vals = []
                    try:
                        subkey = winreg.OpenKey(hive, subkey_path)
                        try:
                            k = 0
                            while True:
                                try:
                                    vname, vdata, vtype = winreg.EnumValue(subkey, k)
                                    subkey_vals.append({"name": vname, "data": str(vdata), "type": vtype})
                                    k += 1
                                except OSError:
                                    break
                        finally:
                            winreg.CloseKey(subkey)
                    except Exception:
                        pass
                    results.append({"subkey": subkey_name, "values": subkey_vals})
                    j += 1
                except OSError:
                    break
    except Exception as e:
        results.append({"error": str(e), "path": path})
    finally:
        winreg.CloseKey(key)
    return results


def collect_registry():
    if not IS_WINDOWS:
        return {"error": "Registry collection only supported on Windows"}

    persistence_keys = {
        "HKLM_Run":               (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     False),
        "HKLM_RunOnce":           (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", False),
        "HKCU_Run":               (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     False),
        "HKCU_RunOnce":           (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", False),
        "HKLM_Run_Wow64":         (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", False),
        "HKLM_Winlogon":          (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", False),
        "HKLM_Services":          (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services",  True),
        "HKLM_AppInit":           (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", False),
        "HKCU_Startup":           (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", False),
        "HKLM_ImageFileExecution":(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", True),
        "HKLM_LSA":               (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", False),
    }

    results = {}
    for key_name, (hive, path, enum_sub) in persistence_keys.items():
        results[key_name] = read_reg_key(hive, path, enumerate_subkeys=enum_sub)

    results["powershell_persistence_check"] = run_powershell("""\
$keys = @(
    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
    'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'
)
foreach($k in $keys){
    Write-Output "=== $k ==="
    Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | Format-List
}
""")
    results["installed_software"] = run_powershell("""\
Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
Where-Object {$_.DisplayName} | Sort-Object DisplayName | ConvertTo-Json
""", timeout=60)
    return results


# ─────────────────────────────────────────────
# 5. EVENT LOGS
# ─────────────────────────────────────────────
def collect_event_logs():
    logs = {}
    logs["security_logon"]      = run_powershell("""\
Get-EventLog -LogName Security -Newest 200 -InstanceId 4624,4625,4648,4672,4720,4728,4732,4756 -ErrorAction SilentlyContinue |
Select-Object TimeGenerated, EventID, EntryType, Message | ConvertTo-Json -Depth 2
""", timeout=90)
    logs["system_critical"]     = run_powershell("""\
Get-EventLog -LogName System -Newest 100 -EntryType Error,Warning -ErrorAction SilentlyContinue |
Select-Object TimeGenerated, EventID, Source, EntryType, Message | ConvertTo-Json -Depth 2
""", timeout=60)
    logs["application_errors"]  = run_powershell("""\
Get-EventLog -LogName Application -Newest 100 -EntryType Error -ErrorAction SilentlyContinue |
Select-Object TimeGenerated, EventID, Source, Message | ConvertTo-Json -Depth 2
""", timeout=60)
    logs["powershell_scriptblock"] = run_powershell("""\
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 100 -ErrorAction SilentlyContinue |
Where-Object {$_.Id -in @(4103,4104)} |
Select-Object TimeCreated, Id, Message | ConvertTo-Json -Depth 2
""", timeout=60)
    logs["task_scheduler"]      = run_powershell("""\
Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 50 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, Message | ConvertTo-Json -Depth 2
""", timeout=60)
    logs["defender_events"]     = run_powershell("""\
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 50 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, LevelDisplayName, Message | ConvertTo-Json -Depth 2
""", timeout=60)
    logs["rdp_sessions"]        = run_powershell("""\
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -MaxEvents 50 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, Message | ConvertTo-Json -Depth 2
""", timeout=60)
    return logs


# ─────────────────────────────────────────────
# 6. FILESYSTEM
# ─────────────────────────────────────────────
def collect_filesystem_artifacts():
    artifacts = {}
    artifacts["prefetch_list"] = run_powershell("""\
$pf = 'C:\\Windows\\Prefetch'
if(Test-Path $pf){
    Get-ChildItem $pf -Filter *.pf |
    Select-Object Name, LastWriteTime, CreationTime, Length |
    Sort-Object LastWriteTime -Descending | ConvertTo-Json
} else { 'Prefetch directory not found or access denied' }
""")
    artifacts["recent_files"] = run_powershell("""\
$recent = [Environment]::GetFolderPath('Recent')
Get-ChildItem $recent |
Select-Object Name, LastWriteTime, CreationTime |
Sort-Object LastWriteTime -Descending | Select-Object -First 100 | ConvertTo-Json
""")
    artifacts["temp_executables"] = run_powershell("""\
$temps = @($env:TEMP, $env:TMP, 'C:\\Windows\\Temp')
$results = @()
foreach($t in $temps){
    if(Test-Path $t){
        $results += Get-ChildItem $t -File -ErrorAction SilentlyContinue |
        Where-Object {$_.Extension -in '.exe','.dll','.bat','.ps1','.vbs','.js','.scr','.com'} |
        Select-Object FullName, LastWriteTime, Length,
        @{N='Hash';E={(Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash}}
    }
}
$results | ConvertTo-Json
""", timeout=90)
    artifacts["ads_detection"] = run_powershell("""\
$userPath = $env:USERPROFILE
Get-ChildItem $userPath -Recurse -ErrorAction SilentlyContinue |
Get-Item -Stream * -ErrorAction SilentlyContinue |
Where-Object {$_.Stream -ne ':$DATA'} |
Select-Object FileName, Stream, Length | Select-Object -First 50 | ConvertTo-Json
""", timeout=60)
    artifacts["volume_info"]              = run_cmd("fsutil volume diskfree C:")
    artifacts["ntfs_info"]                = run_cmd("fsutil fsinfo ntfsinfo C:")
    artifacts["recently_modified_system"] = run_powershell("""\
Get-ChildItem 'C:\\Windows\\System32' -File -ErrorAction SilentlyContinue |
Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
Select-Object Name, LastWriteTime, Length |
Sort-Object LastWriteTime -Descending | Select-Object -First 50 | ConvertTo-Json
""", timeout=60)
    return artifacts


# ─────────────────────────────────────────────
# 7. BROWSER
# ─────────────────────────────────────────────
def collect_browser_artifacts():
    browsers = {}
    chrome_paths = {
        "history":    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History"),
        "downloads":  os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History"),
        "cookies":    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies"),
        "login_data": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"),
        "extensions": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions"),
    }
    edge_paths = {
        "history":    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History"),
        "extensions": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions"),
    }
    firefox_profile = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")

    def check_browser_files(name, paths):
        result = {}
        for artifact, path in paths.items():
            if os.path.exists(path):
                stat = os.stat(path)
                note = "File exists - copy with forensic tools for SQLite analysis"
                if artifact == "downloads" and "History" in path:
                    note = "Downloads table is stored inside the History SQLite DB (Chrome design). Use forensic copy."
                result[artifact] = {
                    "path": path, "exists": True,
                    "size_bytes": stat.st_size,
                    "last_modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "note": note
                }
            else:
                result[artifact] = {"path": path, "exists": False}
        return result

    browsers["chrome"]                  = check_browser_files("Chrome", chrome_paths)
    browsers["edge"]                    = check_browser_files("Edge", edge_paths)
    browsers["firefox_profile_exists"]  = os.path.exists(firefox_profile)
    browsers["chrome_extensions"]       = run_powershell("""\
$extPath = "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Extensions"
if(Test-Path $extPath){
    Get-ChildItem $extPath -Directory | ForEach-Object {
        $manifest = Get-ChildItem $_.FullName -Recurse -Filter manifest.json -ErrorAction SilentlyContinue | Select-Object -First 1
        if($manifest){
            $data = Get-Content $manifest.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
            [PSCustomObject]@{ ID=$_.Name; Name=$data.name; Version=$data.version; Description=$data.description }
        }
    } | ConvertTo-Json
}
""", timeout=60)
    browsers["ie_history_note"]         = "IE index.dat legacy format. Modern Edge uses SQLite. See edge artifact path above."
    browsers["ps_download_history"]     = run_powershell("""\
Get-ChildItem "$env:USERPROFILE\\Downloads" |
Select-Object Name, CreationTime, LastWriteTime, Length,
@{N='Hash';E={(Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash}} |
Sort-Object CreationTime -Descending | ConvertTo-Json
""")
    return browsers


# ─────────────────────────────────────────────
# 8. TASKS & SERVICES
# ─────────────────────────────────────────────
def collect_tasks_services():
    data = {}
    data["scheduled_tasks"] = run_powershell("""\
Get-ScheduledTask |
Select-Object TaskName, TaskPath, State,
@{N='Author';E={$_.Principal.UserId}},
@{N='RunAs';E={$_.Principal.RunLevel}},
@{N='Actions';E={($_.Actions | ForEach-Object {"$($_.Execute) $($_.Arguments)"}) -join '; '}},
@{N='Triggers';E={($_.Triggers | ForEach-Object {$_.CimClass.CimClassName}) -join '; '}} |
ConvertTo-Json -Depth 3
""", timeout=60)
    data["services_all"]    = run_powershell("""\
Get-Service | Select-Object Name, DisplayName, Status, StartType |
Sort-Object Status | ConvertTo-Json
""")
    data["services_running"] = run_powershell("""\
Get-WmiObject Win32_Service |
Where-Object {$_.State -eq 'Running'} |
Select-Object Name, DisplayName, State, StartMode, PathName, StartName,
@{N='Hash';E={
    $path = ($_.PathName -replace '"','') -split ' ' | Select-Object -First 1
    if($path -and (Test-Path $path)){(Get-FileHash $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash}else{'N/A'}
}} | ConvertTo-Json -Depth 2
""", timeout=90)
    data["services_suspicious_paths"] = run_powershell("""\
Get-WmiObject Win32_Service |
Where-Object {$_.PathName -notmatch 'System32|SysWOW64|Program Files' -and $_.PathName -ne $null} |
Select-Object Name, DisplayName, State, PathName, StartName | ConvertTo-Json
""")
    data["drivers"]       = run_cmd("driverquery /v /fo csv")
    data["startup_items"] = run_powershell("""\
Get-CimInstance Win32_StartupCommand |
Select-Object Name, Command, Location, User | ConvertTo-Json
""")
    return data


# ─────────────────────────────────────────────
# 9. MEMORY
# ─────────────────────────────────────────────
def collect_memory_info():
    mem = {}
    mem["physical_memory"]       = run_powershell("""\
Get-WmiObject Win32_PhysicalMemory |
Select-Object BankLabel, Capacity, Speed, Manufacturer, PartNumber | ConvertTo-Json
""")
    mem["memory_usage"]          = run_powershell("""\
Get-WmiObject Win32_OperatingSystem |
Select-Object @{N='TotalRAM_GB';E={[math]::Round($_.TotalVisibleMemorySize/1MB,2)}},
@{N='FreeRAM_GB';E={[math]::Round($_.FreePhysicalMemory/1MB,2)}},
@{N='UsedRAM_GB';E={[math]::Round(($_.TotalVisibleMemorySize-$_.FreePhysicalMemory)/1MB,2)}},
@{N='Usage_Pct';E={[math]::Round(($_.TotalVisibleMemorySize-$_.FreePhysicalMemory)/$_.TotalVisibleMemorySize*100,1)}} |
ConvertTo-Json
""")
    mem["top_processes_by_memory"] = run_powershell("""\
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 20 |
Select-Object ProcessName, Id,
@{N='RAM_MB';E={[math]::Round($_.WorkingSet/1MB,2)}},
@{N='CPU_s';E={[math]::Round($_.CPU,2)}}, Path | ConvertTo-Json
""")
    mem["pagefile_info"]         = run_powershell("""\
Get-WmiObject Win32_PageFileUsage |
Select-Object Name, AllocatedBaseSize, CurrentUsage, PeakUsage | ConvertTo-Json
""")
    mem["process_handles"]       = run_powershell("""\
Get-Process | Sort-Object Handles -Descending | Select-Object -First 20 |
Select-Object ProcessName, Id, Handles, Threads, @{N='Modules';E={$_.Modules.Count}} | ConvertTo-Json
""")
    mem["suspicious_modules"]    = run_powershell("""\
Get-Process | ForEach-Object {
    $proc = $_
    $mods = $null
    try { $mods = $_.Modules } catch { $mods = @() }
    if ($mods) {
        $mods | ForEach-Object {
            if($_.FileName -notmatch 'Windows|Program Files|Microsoft' -and $_.FileName -ne $null){
                [PSCustomObject]@{
                    Process = $proc.Name; PID = $proc.Id
                    Module  = $_.FileName; Size = $_.ModuleMemorySize
                }
            }
        }
    }
} | Select-Object -First 100 | ConvertTo-Json
""", timeout=120)
    mem["ram_dump_note"] = {
        "info":               "Full RAM dump requires winpmem, DumpIt, or similar tool with kernel driver.",
        "command_winpmem":    "winpmem_mini_x64.exe memory.dmp",
        "command_dumpit":     "DumpIt.exe /O memory.dmp /T RAW",
        "volatility_analysis":"volatility3 -f memory.dmp windows.pslist",
        "size_estimate_gb":   run_powershell(
            "(Get-WmiObject Win32_OperatingSystem).TotalVisibleMemorySize/1MB | ForEach-Object {[math]::Round($_,2)}"
        )
    }
    return mem


# ─────────────────────────────────────────────
# 10. USERS
# ─────────────────────────────────────────────
def collect_users():
    users = {}
    users["local_users"]    = run_powershell("""\
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet,
PasswordRequired, UserMayChangePassword, Description | ConvertTo-Json
""")
    users["local_groups"]   = run_powershell("Get-LocalGroup | Select-Object Name, Description | ConvertTo-Json")
    users["admin_members"]  = run_powershell("""\
Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
Select-Object Name, ObjectClass, PrincipalSource | ConvertTo-Json
""")
    users["active_sessions"] = run_cmd("query session")
    users["logged_on_users"] = run_cmd("query user")
    users["net_users"]       = run_cmd("net user")
    users["recent_logons"]   = run_powershell("""\
Get-EventLog -LogName Security -InstanceId 4624 -Newest 50 -ErrorAction SilentlyContinue |
Select-Object TimeGenerated, Message | ConvertTo-Json -Depth 2
""", timeout=60)
    return users


# ─────────────────────────────────────────────
# YARDIMCI FONKSİYONLAR
# ─────────────────────────────────────────────
def _extract_hashes_from_results(result):
    """Toplanan process/service verisinden SHA256 hash listesi çıkarır."""
    hashes = []
    seen   = set()

    def _parse(raw, name_key, path_key, source):
        if not isinstance(raw, str) or not raw:
            return
        if "[ERROR]" in raw or "[TIMEOUT]" in raw:
            return
        try:
            items = json.loads(raw)
            if isinstance(items, dict):
                items = [items]
            for item in items:
                h = (item.get("Hash") or "").upper().strip()
                if h and h not in ("N/A", "HASH_ERROR", "") and h not in seen:
                    seen.add(h)
                    hashes.append({
                        "hash":   h,
                        "name":   item.get(name_key, "unknown"),
                        "path":   item.get(path_key) or "unknown",
                        "source": source
                    })
        except Exception:
            pass

    _parse(result.get("processes", {}).get("processes", ""),         "ProcessName", "Path",     "process")
    _parse(result.get("tasks_services", {}).get("services_running", ""), "Name",   "PathName",  "service")
    return hashes


def _find_data_dir(subdir):
    """IOC ve YARA dizinlerini script ve PyInstaller EXE modunda bulur."""
    candidates = []
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(script_dir, '..', subdir))
    candidates.append(os.path.join(script_dir, subdir))
    try:
        candidates.append(os.path.join(sys._MEIPASS, subdir))
    except AttributeError:
        pass
    for c in candidates:
        if os.path.exists(c):
            return os.path.normpath(c)
    return None


# ─────────────────────────────────────────────
# 11. IOC HASH KARŞILAŞTIRMA
# ─────────────────────────────────────────────
def collect_ioc_matches(all_hashes):
    results = {"matches": [], "ioc_count": 0, "checked_count": len(all_hashes), "error": None}

    ioc_dir = _find_data_dir("ioc")
    if not ioc_dir:
        results["error"] = "IOC dizini bulunamadı"
        return results

    ioc_file = os.path.join(ioc_dir, "hashes.txt")
    if not os.path.exists(ioc_file):
        results["error"] = f"IOC hash dosyası bulunamadı: {ioc_file}"
        return results

    try:
        with open(ioc_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        ioc_set = set()
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                ioc_set.add(line.upper())

        results["ioc_count"] = len(ioc_set)

        for item in all_hashes:
            h = item.get("hash", "").upper()
            if h and h in ioc_set:
                results["matches"].append({
                    "hash":     h,
                    "name":     item.get("name", "unknown"),
                    "path":     item.get("path", "unknown"),
                    "source":   item.get("source", "unknown"),
                    "severity": "CRITICAL"
                })
    except Exception as e:
        results["error"] = str(e)

    return results


# ─────────────────────────────────────────────
# 12. LOLBAS / ŞÜPHELİ COMMANDLINE
# ─────────────────────────────────────────────
def collect_lolbas():
    PATTERNS = {
        "powershell": [
            (r"-[Ee][Nn][Cc](\b|oded)",                              "Encoded command (obfuscation)"),
            (r"[Ii][Ee][Xx]\s*[\(\|]|Invoke-Expression",             "IEX / Invoke-Expression"),
            (r"DownloadString|DownloadFile|WebClient|Net\.WebClient", "Download cradle"),
            (r"-[Ww]indow[Ss]tyle\s+[Hh]idden|WindowStyle\s+1",     "Hidden window"),
            (r"-[Ee]xecution[Pp]olicy\s+[Bb]ypass",                 "ExecutionPolicy bypass"),
            (r"FromBase64String",                                      "Base64 decode"),
            (r"Invoke-Mimikatz|sekurlsa|lsadump",                     "Mimikatz keywords"),
            (r"Invoke-Shellcode|ReflectivePEInjection",               "Shellcode injection"),
        ],
        "rundll32": [
            (r"javascript:|vbscript:",                                 "Script via rundll32"),
            (r"url\.dll.*(OpenURL|FileProtocolHandler)",               "URL handler abuse"),
            (r"advpack.*LaunchINFSection",                             "INF section launch"),
            (r"scrobj\.dll",                                           "Scriptlet execution"),
        ],
        "regsvr32": [
            (r"/[Ss]\s+/[Nn]\s+/[Uu]\s+/[Ii]:",                     "Squiblydoo technique"),
            (r"scrobj\.dll",                                           "Scriptlet execution"),
            (r"https?://",                                             "Remote scriptlet"),
        ],
        "certutil": [
            (r"-[Uu][Rr][Ll][Cc][Aa][Cc][Hh][Ee]",                   "URL cache download"),
            (r"-[Dd][Ee][Cc][Oo][Dd][Ee]",                            "Base64 decode"),
            (r"https?://",                                             "Remote resource access"),
        ],
        "mshta": [
            (r"https?://",                                             "Remote HTA execution"),
            (r"vbscript:|javascript:",                                 "Inline script execution"),
            (r"\\\\",                                                  "UNC path execution"),
        ],
        "wscript":   [(r"\\[Tt][Ee][Mm][Pp]\\",                      "Script from TEMP")],
        "cscript":   [(r"\\[Tt][Ee][Mm][Pp]\\",                      "Script from TEMP")],
        "bitsadmin": [(r"/[Tt][Rr][Aa][Nn][Ss][Ff][Ee][Rr]",         "BITS transfer (download)")],
        "schtasks":  [(r"/[Cc][Rr][Ee][Aa][Tt][Ee].*powershell",     "Scheduled PowerShell")],
        "odbcconf":  [(r"/[Aa]\s*\{[Rr][Ee][Gg][Ss][Vv][Rr]",       "REGSVR via odbcconf")],
    }

    raw = run_powershell("""\
Get-WmiObject Win32_Process |
Select-Object ProcessId, Name, CommandLine, ParentProcessId |
ConvertTo-Json -Depth 2
""", timeout=60)

    findings = []
    try:
        procs = []
        if raw and "[ERROR]" not in raw and "[TIMEOUT]" not in raw:
            procs = json.loads(raw)
            if isinstance(procs, dict):
                procs = [procs]
        for proc in procs:
            pname   = (proc.get("Name") or "").lower().replace(".exe", "")
            cmdline = proc.get("CommandLine") or ""
            if pname in PATTERNS:
                for pattern, desc in PATTERNS[pname]:
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        findings.append({
                            "process":     proc.get("Name"),
                            "pid":         proc.get("ProcessId"),
                            "ppid":        proc.get("ParentProcessId"),
                            "commandline": cmdline[:800],
                            "detection":   desc,
                            "severity":    "HIGH"
                        })
                        break
    except Exception as e:
        return {"error": str(e), "findings": []}

    return {"findings": findings, "total_found": len(findings)}


# ─────────────────────────────────────────────
# 13. WEBSHELL TARAMA
# ─────────────────────────────────────────────
def collect_webshell_scan():
    WEB_DIRS = [
        r"C:\inetpub\wwwroot", r"C:\inetpub\ftproot",
        r"C:\xampp\htdocs",   r"C:\xampp\cgi-bin",
        r"C:\wamp\www",       r"C:\wamp64\www",
        r"C:\nginx\html",     r"C:\Apache24\htdocs",
    ]
    WEB_EXTS  = {'.php', '.asp', '.aspx', '.jsp', '.jspx', '.cfm', '.shtml', '.phtml'}
    SKIP_DIRS = {'node_modules', '.git', 'vendor', '__pycache__', '.svn'}
    PATTERNS  = [
        (r"eval\s*\(\s*base64_decode",                                "PHP eval+base64_decode"),
        (r"eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)",                 "PHP eval+superglobal"),
        (r"system\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)",               "PHP system()+superglobal"),
        (r"shell_exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)",           "PHP shell_exec()+superglobal"),
        (r"exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)",                 "PHP exec()+superglobal"),
        (r"passthru\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)",             "PHP passthru()+superglobal"),
        (r"preg_replace\s*\(.*\/e[\"']",                              "PHP preg_replace /e (RCE)"),
        (r"assert\s*\(\s*\$_(POST|GET|REQUEST)",                      "PHP assert()+superglobal"),
        (r"gzinflate\s*\(.*base64_decode",                            "PHP gzinflate+base64"),
        (r"\$_(POST|GET|REQUEST)\[.{0,40}\]\s*\(\s*\$_(POST|GET|REQUEST)", "PHP variable function call"),
        (r"<%.{0,100}Runtime\.getRuntime\(\)\.exec",                  "JSP Runtime.exec()"),
        (r"<%.{0,100}ProcessBuilder",                                  "JSP ProcessBuilder"),
        (r"WScript\.Shell.{0,30}(Exec|Run)",                          "ASP WScript.Shell"),
        (r"CreateObject\(.{0,30}WScript\.Shell",                       "ASP CreateObject WScript"),
        (r"Server\.CreateObject\(.{0,30}ADODB\.Stream",               "ASP ADODB.Stream"),
    ]

    results = {"scanned_dirs": [], "findings": [], "total_files_scanned": 0, "total_findings": 0}

    for web_dir in WEB_DIRS:
        if not os.path.exists(web_dir):
            continue
        results["scanned_dirs"].append(web_dir)
        for root, dirs, files in os.walk(web_dir):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
            for fname in files:
                if os.path.splitext(fname)[1].lower() not in WEB_EXTS:
                    continue
                fpath = os.path.join(root, fname)
                results["total_files_scanned"] += 1
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read(65536)
                    for pattern, desc in PATTERNS:
                        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                            stat = os.stat(fpath)
                            results["findings"].append({
                                "file":          fpath,
                                "detection":     desc,
                                "size_bytes":    stat.st_size,
                                "last_modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                "severity":      "CRITICAL"
                            })
                            break
                except Exception:
                    continue

    results["total_findings"] = len(results["findings"])
    return results


# ─────────────────────────────────────────────
# 14. VIRUSTOTAL
# ─────────────────────────────────────────────
def collect_virustotal(all_hashes, api_key):
    results = {
        "api_key_provided": bool(api_key),
        "queried": 0, "clean": 0, "malicious": 0,
        "suspicious": 0, "not_found": 0, "errors": 0,
        "findings": [],
        "note": "Free API: 4 istek/dakika. Max 20 hash sorgulanır (15s bekleme)."
    }

    if not api_key:
        results["error"] = "API key yok. --vt-key argümanını kullan."
        return results

    seen  = set()
    valid = []
    for item in all_hashes:
        h = item.get("hash", "").strip().upper()
        if h and h not in ("N/A", "HASH_ERROR", "") and len(h) == 64 and h not in seen:
            seen.add(h)
            valid.append(item)

    results["total_unique_hashes"] = len(valid)

    for item in valid[:20]:
        h = item.get("hash", "").strip().lower()
        try:
            req = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/files/{h}",
                headers={"x-apikey": api_key}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            stats      = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious  = stats.get("malicious",  0)
            suspicious = stats.get("suspicious", 0)
            results["queried"] += 1

            entry = {
                "hash": h.upper(), "name": item.get("name", "unknown"),
                "path": item.get("path", "unknown"), "source": item.get("source", "unknown"),
                "malicious": malicious, "suspicious": suspicious,
                "undetected": stats.get("undetected", 0),
                "vt_link": f"https://www.virustotal.com/gui/file/{h}"
            }
            if malicious > 0:
                results["malicious"] += 1
                entry["verdict"] = "MALICIOUS"; entry["severity"] = "CRITICAL"
                results["findings"].append(entry)
            elif suspicious > 0:
                results["suspicious"] += 1
                entry["verdict"] = "SUSPICIOUS"; entry["severity"] = "HIGH"
                results["findings"].append(entry)
            else:
                results["clean"] += 1

        except urllib.error.HTTPError as e:
            if e.code == 404:
                results["not_found"] += 1
            elif e.code == 429:
                results["errors"] += 1
                results["rate_limit_hit"] = True
                break
            else:
                results["errors"] += 1
        except Exception:
            results["errors"] += 1

        time.sleep(15)

    return results


# ─────────────────────────────────────────────
# 15. YARA
# ─────────────────────────────────────────────
def collect_yara_scan(rules_dir=None):
    results = {
        "yara_available": False, "rules_loaded": 0,
        "files_scanned": 0, "findings": [], "errors": []
    }

    try:
        import yara
        results["yara_available"] = True
    except ImportError:
        results["error"] = "yara-python kurulu değil. 'pip install yara-python' çalıştır."
        return results

    if not rules_dir:
        rules_dir = _find_data_dir("yara_rules")
    if not rules_dir or not os.path.exists(rules_dir):
        results["error"] = "YARA rules dizini bulunamadı"
        return results

    compiled_rules = []
    for rf in os.listdir(rules_dir):
        if not rf.lower().endswith(('.yar', '.yara')):
            continue
        try:
            rules = yara.compile(filepath=os.path.join(rules_dir, rf))
            compiled_rules.append((rf, rules))
            results["rules_loaded"] += 1
        except Exception as e:
            results["errors"].append(f"Derleme hatası {rf}: {str(e)}")

    if not compiled_rules:
        results["error"] = "Hiç YARA kuralı derlenemedi"
        return results

    scan_targets = []

    for temp_dir in [os.environ.get("TEMP",""), os.environ.get("TMP",""), r"C:\Windows\Temp"]:
        if temp_dir and os.path.exists(temp_dir):
            try:
                for f in os.listdir(temp_dir):
                    if f.lower().endswith(('.exe','.dll','.ps1','.vbs','.js','.bat','.scr')):
                        scan_targets.append(os.path.join(temp_dir, f))
            except Exception:
                pass

    sys32  = r"C:\Windows\System32"
    cutoff = datetime.datetime.now() - datetime.timedelta(days=7)
    if os.path.exists(sys32):
        try:
            for f in os.listdir(sys32):
                fp = os.path.join(sys32, f)
                if os.path.isfile(fp):
                    try:
                        if datetime.datetime.fromtimestamp(os.path.getmtime(fp)) > cutoff:
                            scan_targets.append(fp)
                    except Exception:
                        pass
        except Exception:
            pass

    for web_dir in [r"C:\inetpub\wwwroot", r"C:\xampp\htdocs", r"C:\wamp\www"]:
        if os.path.exists(web_dir):
            try:
                for root, dirs, files in os.walk(web_dir):
                    dirs[:] = [d for d in dirs if d.lower() not in ('node_modules', '.git')]
                    for f in files[:30]:
                        scan_targets.append(os.path.join(root, f))
            except Exception:
                pass

    downloads = os.path.join(os.environ.get("USERPROFILE", ""), "Downloads")
    if os.path.exists(downloads):
        try:
            for f in os.listdir(downloads):
                if f.lower().endswith(('.exe','.dll','.ps1','.vbs','.js','.bat','.zip','.rar')):
                    scan_targets.append(os.path.join(downloads, f))
        except Exception:
            pass

    for fpath in scan_targets[:300]:
        if not os.path.isfile(fpath):
            continue
        results["files_scanned"] += 1
        for rule_file, rules in compiled_rules:
            try:
                matches = rules.match(fpath, timeout=10)
                if matches:
                    stat = os.stat(fpath)
                    results["findings"].append({
                        "file":          fpath,
                        "rule_file":     rule_file,
                        "matched_rules": [m.rule for m in matches],
                        "tags":          [tag for m in matches for tag in m.tags],
                        "size_bytes":    stat.st_size,
                        "last_modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "severity":      "HIGH"
                    })
            except Exception as e:
                results["errors"].append(f"{os.path.basename(fpath)}: {str(e)[:80]}")

    return results


# ─────────────────────────────────────────────
# ORCHESTRATOR
# ─────────────────────────────────────────────
def collect_all(progress_callback=None, partial_ref=None, vt_api_key=None, yara_rules_dir=None):

    def update(msg, pct):
        if progress_callback:
            progress_callback(msg, pct)
        else:
            print(f"[{pct:3d}%] {msg}")

    result = {
        "meta": {
            "tool":       "TEA Forensic Collector",
            "version":    "1.1.0",
            "start_time": datetime.datetime.now().isoformat(),
            "platform":   platform.platform()
        }
    }

    standard = [
        ("System Information",         collect_system_info,         "system_info",    5),
        ("Process List",               collect_processes,            "processes",      13),
        ("Network Connections",        collect_network,              "network",        21),
        ("Registry Persistence",       collect_registry,             "registry",       30),
        ("Event Logs",                 collect_event_logs,           "event_logs",     40),
        ("Filesystem Artifacts",       collect_filesystem_artifacts, "filesystem",     48),
        ("Browser Artifacts",          collect_browser_artifacts,    "browsers",       55),
        ("Scheduled Tasks & Services", collect_tasks_services,       "tasks_services", 62),
        ("Memory Information",         collect_memory_info,          "memory",         69),
        ("User Accounts",              collect_users,                "users",          75),
    ]

    for name, func, key, pct in standard:
        update(f"Collecting: {name}...", pct)
        try:
            result[key] = func()
        except Exception as e:
            result[key] = {"error": str(e)}
        if partial_ref is not None:
            partial_ref.update(result)

    update("Building hash inventory...", 78)
    all_hashes = _extract_hashes_from_results(result)
    result["meta"]["total_hashes_collected"] = len(all_hashes)

    update("IOC Hash Comparison...", 81)
    try:
        result["ioc_matches"] = collect_ioc_matches(all_hashes)
    except Exception as e:
        result["ioc_matches"] = {"error": str(e)}
    if partial_ref is not None:
        partial_ref.update(result)

    update("LOLBAS / Suspicious Commandline Detection...", 85)
    try:
        result["lolbas"] = collect_lolbas()
    except Exception as e:
        result["lolbas"] = {"error": str(e)}
    if partial_ref is not None:
        partial_ref.update(result)

    update("Webshell Scan...", 88)
    try:
        result["webshell"] = collect_webshell_scan()
    except Exception as e:
        result["webshell"] = {"error": str(e)}
    if partial_ref is not None:
        partial_ref.update(result)

    update("YARA Scan...", 92)
    try:
        result["yara"] = collect_yara_scan(yara_rules_dir)
    except Exception as e:
        result["yara"] = {"error": str(e)}
    if partial_ref is not None:
        partial_ref.update(result)

    if vt_api_key:
        update("VirusTotal Reputation Check (yavaş olabilir)...", 96)
    else:
        update("VirusTotal skipped (--vt-key girilmedi)...", 96)
    try:
        result["virustotal"] = collect_virustotal(all_hashes, vt_api_key)
    except Exception as e:
        result["virustotal"] = {"error": str(e)}
    if partial_ref is not None:
        partial_ref.update(result)

    result["meta"]["end_time"] = datetime.datetime.now().isoformat()
    result["meta"]["duration_seconds"] = int(
        (
            datetime.datetime.fromisoformat(result["meta"]["end_time"]) -
            datetime.datetime.fromisoformat(result["meta"]["start_time"])
        ).total_seconds()
    )

    return result
