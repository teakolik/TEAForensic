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

# ─────────────────────────────────────────────
# TOOL SELF-FILTER
# Tool'un kendi PID'i ve spawn ettiği child process'lerin PID'leri.
# Tüm tespit modülleri bu set'e karşı filtreler — kendi komutlarını ihbar etmez.
# ─────────────────────────────────────────────
_TOOL_OWN_PID  = os.getpid()
_TOOL_PIDS     = {_TOOL_OWN_PID}   # başlangıçta sadece kendisi; collect_all() doldurur

# Tool'un ürettiği PowerShell komut imzaları
_TOOL_PS_SIGNATURES = [
    "Get-WmiObject Win32_Process",
    "Get-WmiObject Win32_Service",
    "Get-WmiObject Win32_PhysicalMemory",
    "Get-WmiObject Win32_OperatingSystem",
    "Get-AuthenticodeSignature",
    "Get-NetTCPConnection",
    "Get-NetFirewallRule",
    "Get-ScheduledTask",
    "Get-LocalUser",
    "Get-LocalGroup",
    "Get-LocalGroupMember",
    "Get-ItemProperty HKLM:",
    "Get-ItemProperty HKCU:",
    "Get-ChildItem.*Prefetch",
    "Get-ChildItem.*Downloads",
    "Get-ChildItem.*System32",
    "ConvertTo-Json",
    "-NonInteractive -ExecutionPolicy Bypass -Command",
]

def _is_tool_process(pid, ppid, cmdline):
    """Bu process tool'un kendisi veya tool tarafından spawn edilmiş mi?"""
    if pid in _TOOL_PIDS:
        return True
    if ppid in _TOOL_PIDS:
        _TOOL_PIDS.add(pid)   # geç gelen child'ları da listeye ekle
        return True
    if cmdline and any(sig in cmdline for sig in _TOOL_PS_SIGNATURES):
        return True
    return False


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

# XML'den tek bir data alanı güvenli çeker
_XML_HELPER = r"""
function Get-XmlField {
    param([xml]$xml, [string]$name)
    try {
        $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $name }
        if ($node) { return $node.'#text' } else { return $null }
    } catch { return $null }
}
"""

def collect_event_logs():
    logs = {}

    # ── 4624 Başarılı Oturum Açma — XML parse ile tam field extraction ────────
    logs["security_logon_success"] = run_powershell(_XML_HELPER + r"""
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 100 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    try {
        $xml = [xml]$e.ToXml()
        [PSCustomObject]@{
            TimeCreated    = $e.TimeCreated.ToString('o')
            EventID        = $e.Id
            SubjectUser    = Get-XmlField $xml 'SubjectUserName'
            SubjectDomain  = Get-XmlField $xml 'SubjectDomainName'
            TargetUser     = Get-XmlField $xml 'TargetUserName'
            TargetDomain   = Get-XmlField $xml 'TargetDomainName'
            LogonType      = Get-XmlField $xml 'LogonType'
            LogonTypeName  = switch (Get-XmlField $xml 'LogonType') {
                '2'  {'Interactive'}
                '3'  {'Network'}
                '4'  {'Batch'}
                '5'  {'Service'}
                '7'  {'Unlock'}
                '8'  {'NetworkCleartext'}
                '9'  {'NewCredentials'}
                '10' {'RemoteInteractive'}
                '11' {'CachedInteractive'}
                default {'Unknown'}
            }
            IpAddress      = Get-XmlField $xml 'IpAddress'
            IpPort         = Get-XmlField $xml 'IpPort'
            ProcessName    = Get-XmlField $xml 'ProcessName'
            WorkstationName= Get-XmlField $xml 'WorkstationName'
            LogonGuid      = Get-XmlField $xml 'LogonGuid'
        }
    } catch { $null }
}
$results | Where-Object {$_ -ne $null} | ConvertTo-Json -Depth 2 -Compress
""", timeout=90)

    # ── 4625 Başarısız Oturum Açma — brute force tespiti ─────────────────────
    logs["security_logon_failure"] = run_powershell(_XML_HELPER + r"""
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 100 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    try {
        $xml = [xml]$e.ToXml()
        [PSCustomObject]@{
            TimeCreated      = $e.TimeCreated.ToString('o')
            EventID          = $e.Id
            TargetUser       = Get-XmlField $xml 'TargetUserName'
            TargetDomain     = Get-XmlField $xml 'TargetDomainName'
            FailureReason    = Get-XmlField $xml 'FailureReason'
            Status           = Get-XmlField $xml 'Status'
            SubStatus        = Get-XmlField $xml 'SubStatus'
            LogonType        = Get-XmlField $xml 'LogonType'
            IpAddress        = Get-XmlField $xml 'IpAddress'
            WorkstationName  = Get-XmlField $xml 'WorkstationName'
            CallerProcessName= Get-XmlField $xml 'ProcessName'
        }
    } catch { $null }
}
$results | Where-Object {$_ -ne $null} | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── 4648 Açık kimlik bilgisiyle oturum açma (runas / pass-the-hash indikatörü)
    logs["security_explicit_creds"] = run_powershell(_XML_HELPER + r"""
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648} -MaxEvents 50 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    try {
        $xml = [xml]$e.ToXml()
        [PSCustomObject]@{
            TimeCreated   = $e.TimeCreated.ToString('o')
            EventID       = $e.Id
            SubjectUser   = Get-XmlField $xml 'SubjectUserName'
            TargetUser    = Get-XmlField $xml 'TargetUserName'
            TargetServer  = Get-XmlField $xml 'TargetServerName'
            ProcessName   = Get-XmlField $xml 'ProcessName'
            IpAddress     = Get-XmlField $xml 'IpAddress'
        }
    } catch { $null }
}
$results | Where-Object {$_ -ne $null} | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── 4672 Özel ayrıcalık atama (admin logon) ───────────────────────────────
    logs["security_privilege_use"] = run_powershell(_XML_HELPER + r"""
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -MaxEvents 50 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    try {
        $xml = [xml]$e.ToXml()
        [PSCustomObject]@{
            TimeCreated  = $e.TimeCreated.ToString('o')
            EventID      = $e.Id
            SubjectUser  = Get-XmlField $xml 'SubjectUserName'
            SubjectDomain= Get-XmlField $xml 'SubjectDomainName'
            Privileges   = Get-XmlField $xml 'PrivilegeList'
        }
    } catch { $null }
}
$results | Where-Object {$_ -ne $null} | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── 4688 Process oluşturma — LOLBAS + komut satırı kaydı ─────────────────
    # NOT: Bu event'in loglanması için Group Policy'de "Audit Process Creation"
    # ve "Include command line in process creation events" açık olmalı.
    logs["security_process_creation"] = run_powershell(_XML_HELPER + r"""
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 200 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    try {
        $xml = [xml]$e.ToXml()
        $cmdLine = Get-XmlField $xml 'CommandLine'
        $newProc = Get-XmlField $xml 'NewProcessName'
        # Gürültüyü azalt: sadece şüpheli veya komut satırlı olanları al
        $interesting = $cmdLine -or
            ($newProc -match 'powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|wmic')
        if ($interesting) {
            [PSCustomObject]@{
                TimeCreated    = $e.TimeCreated.ToString('o')
                EventID        = $e.Id
                SubjectUser    = Get-XmlField $xml 'SubjectUserName'
                NewProcessName = $newProc
                CommandLine    = $cmdLine
                ParentProcess  = Get-XmlField $xml 'ParentProcessName'
                TokenElevation = Get-XmlField $xml 'TokenElevationType'
            }
        }
    } catch { $null }
}
$results | Where-Object {$_ -ne $null} | ConvertTo-Json -Depth 2 -Compress
""", timeout=90)

    # ── 4720/4722/4724/4728/4732/4756 Hesap & Grup değişiklikleri ─────────────
    logs["security_account_changes"] = run_powershell(_XML_HELPER + r"""
$ids = @(4720,4722,4724,4725,4726,4728,4729,4732,4733,4756,4757)
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids} -MaxEvents 100 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$idDesc = @{
    4720='User account created';   4722='User account enabled'
    4724='Password reset attempt'; 4725='User account disabled'
    4726='User account deleted';   4728='Member added to global group'
    4729='Member removed from global group'; 4732='Member added to local group'
    4733='Member removed from local group';  4756='Member added to universal group'
    4757='Member removed from universal group'
}
$results = foreach ($e in $events) {
    try {
        $xml = [xml]$e.ToXml()
        [PSCustomObject]@{
            TimeCreated   = $e.TimeCreated.ToString('o')
            EventID       = $e.Id
            Description   = $idDesc[$e.Id]
            SubjectUser   = Get-XmlField $xml 'SubjectUserName'
            TargetUser    = Get-XmlField $xml 'TargetUserName'
            TargetDomain  = Get-XmlField $xml 'TargetDomainName'
            GroupName     = Get-XmlField $xml 'GroupName'
        }
    } catch { $null }
}
$results | Where-Object {$_ -ne $null} | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── 4776 NTLM Kimlik doğrulama (pass-the-hash indikatörü) ─────────────────
    logs["security_ntlm_auth"] = run_powershell(_XML_HELPER + r"""
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4776} -MaxEvents 100 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    try {
        $xml = [xml]$e.ToXml()
        [PSCustomObject]@{
            TimeCreated      = $e.TimeCreated.ToString('o')
            EventID          = $e.Id
            TargetUser       = Get-XmlField $xml 'TargetUserName'
            Workstation      = Get-XmlField $xml 'Workstation'
            ErrorCode        = Get-XmlField $xml 'Status'
            PackageName      = Get-XmlField $xml 'PackageName'
        }
    } catch { $null }
}
$results | Where-Object {$_ -ne $null} | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── 1102 / 104 Log silme tespiti ──────────────────────────────────────────
    logs["security_log_cleared"] = run_powershell(r"""
$results = @()
# 1102: Security log temizlendi
$sec = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 20 -ErrorAction SilentlyContinue
if ($sec) {
    $results += $sec | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated.ToString('o')
            EventID     = $_.Id
            Channel     = 'Security'
            Message     = 'Security audit log was cleared'
            Severity    = 'CRITICAL'
        }
    }
}
# 104: System log temizlendi
$sys = Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} -MaxEvents 20 -ErrorAction SilentlyContinue
if ($sys) {
    $results += $sys | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated.ToString('o')
            EventID     = $_.Id
            Channel     = 'System'
            Message     = 'System log was cleared'
            Severity    = 'CRITICAL'
        }
    }
}
if ($results.Count -eq 0) { Write-Output '[]'; exit }
$results | ConvertTo-Json -Depth 2 -Compress
""", timeout=30)

    # ── System: Error/Warning ──────────────────────────────────────────────────
    logs["system_critical"] = run_powershell(r"""
$events = Get-WinEvent -FilterHashtable @{LogName='System'; Level=@(1,2,3)} -MaxEvents 100 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    [PSCustomObject]@{
        TimeCreated  = $e.TimeCreated.ToString('o')
        EventID      = $e.Id
        Level        = $e.LevelDisplayName
        ProviderName = $e.ProviderName
        Message      = $e.Message -replace '\s+', ' ' | ForEach-Object { $_.Substring(0, [Math]::Min($_.Length, 500)) }
    }
}
$results | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── Application: Error ────────────────────────────────────────────────────
    logs["application_errors"] = run_powershell(r"""
$events = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=@(1,2)} -MaxEvents 100 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    [PSCustomObject]@{
        TimeCreated  = $e.TimeCreated.ToString('o')
        EventID      = $e.Id
        Level        = $e.LevelDisplayName
        ProviderName = $e.ProviderName
        Message      = $e.Message -replace '\s+', ' ' | ForEach-Object { $_.Substring(0, [Math]::Min($_.Length, 500)) }
    }
}
$results | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── PowerShell Script Block (4103/4104) ───────────────────────────────────
    logs["powershell_scriptblock"] = run_powershell(r"""
$events = Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object {$_.Id -in @(4103,4104)}
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    [PSCustomObject]@{
        TimeCreated  = $e.TimeCreated.ToString('o')
        EventID      = $e.Id
        Description  = if ($e.Id -eq 4104) {'Script Block Logging'} else {'Module Logging'}
        ScriptBlock  = ($e.Message -split '\n' | Select-Object -First 30) -join '\n'
    }
}
$results | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── Task Scheduler ─────────────────────────────────────────────────────────
    logs["task_scheduler"] = run_powershell(r"""
$events = Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 50 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    [PSCustomObject]@{
        TimeCreated  = $e.TimeCreated.ToString('o')
        EventID      = $e.Id
        Description  = switch ($e.Id) {
            106  {'Task registered'}
            140  {'Task updated'}
            141  {'Task deleted'}
            200  {'Task executed'}
            201  {'Task completed'}
            default {$e.LevelDisplayName}
        }
        Message = $e.Message -replace '\s+', ' ' | ForEach-Object { $_.Substring(0, [Math]::Min($_.Length, 300)) }
    }
}
$results | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── Windows Defender ───────────────────────────────────────────────────────
    logs["defender_events"] = run_powershell(r"""
$events = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 50 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    [PSCustomObject]@{
        TimeCreated   = $e.TimeCreated.ToString('o')
        EventID       = $e.Id
        Level         = $e.LevelDisplayName
        Description   = switch ($e.Id) {
            1116 {'Malware detected'}
            1117 {'Malware action taken'}
            1118 {'Malware action failed'}
            1119 {'Malware action succeeded'}
            5001 {'Real-time protection disabled'}
            5004 {'Real-time protection config changed'}
            5007 {'Defender config changed'}
            default {$e.Message -replace '\s+', ' ' | ForEach-Object { $_.Substring(0, [Math]::Min($_.Length, 200)) }}
        }
        RawMessage = $e.Message -replace '\s+', ' ' | ForEach-Object { $_.Substring(0, [Math]::Min($_.Length, 500)) }
    }
}
$results | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── RDP Oturumları ─────────────────────────────────────────────────────────
    logs["rdp_sessions"] = run_powershell(r"""
$events = Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -MaxEvents 50 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated.ToString('o')
        EventID     = $e.Id
        Description = switch ($e.Id) {
            21 {'RDP logon success'}
            22 {'RDP shell started'}
            23 {'RDP logoff'}
            24 {'RDP disconnected'}
            25 {'RDP reconnected'}
            39 {'Session disconnect (same session)'}
            40 {'Session disconnect (different session)'}
            default {$e.LevelDisplayName}
        }
        Message = $e.Message -replace '\s+', ' ' | ForEach-Object { $_.Substring(0, [Math]::Min($_.Length, 300)) }
    }
}
$results | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── WMI Activity — lateral movement / persistence ─────────────────────────
    logs["wmi_activity"] = run_powershell(r"""
$chan = 'Microsoft-Windows-WMI-Activity/Operational'
$events = Get-WinEvent -LogName $chan -MaxEvents 50 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    [PSCustomObject]@{
        TimeCreated  = $e.TimeCreated.ToString('o')
        EventID      = $e.Id
        Level        = $e.LevelDisplayName
        Message      = $e.Message -replace '\s+', ' ' | ForEach-Object { $_.Substring(0, [Math]::Min($_.Length, 500)) }
    }
}
$results | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── BITS Client — download cradle tespiti ─────────────────────────────────
    logs["bits_client"] = run_powershell(r"""
$chan = 'Microsoft-Windows-Bits-Client/Operational'
$events = Get-WinEvent -LogName $chan -MaxEvents 50 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    [PSCustomObject]@{
        TimeCreated  = $e.TimeCreated.ToString('o')
        EventID      = $e.Id
        Description  = switch ($e.Id) {
            3   {'Job created'}
            59  {'Transfer initiated'}
            60  {'Transfer completed'}
            61  {'Transfer error'}
            default {$e.LevelDisplayName}
        }
        Message = $e.Message -replace '\s+', ' ' | ForEach-Object { $_.Substring(0, [Math]::Min($_.Length, 500)) }
    }
}
$results | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── Sysmon (varsa) ─────────────────────────────────────────────────────────
    logs["sysmon"] = run_powershell(r"""
$chan = 'Microsoft-Windows-Sysmon/Operational'
# Kanal yoksa sessizce boş dön
if (-not (Get-WinEvent -ListLog $chan -ErrorAction SilentlyContinue)) {
    Write-Output '{"status":"Sysmon not installed"}'
    exit
}
# En değerli Sysmon event'leri: 1(process), 3(network), 7(image load),
# 8(create remote thread), 10(process access), 11(file create), 22(DNS query)
$events = Get-WinEvent -FilterHashtable @{
    LogName=$chan; Id=@(1,3,7,8,10,11,22)
} -MaxEvents 200 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$results = foreach ($e in $events) {
    [PSCustomObject]@{
        TimeCreated  = $e.TimeCreated.ToString('o')
        EventID      = $e.Id
        Description  = switch ($e.Id) {
            1  {'Process Create'}
            3  {'Network Connection'}
            7  {'Image Loaded'}
            8  {'CreateRemoteThread'}
            10 {'ProcessAccess'}
            11 {'FileCreate'}
            22 {'DNS Query'}
            default {'Sysmon Event'}
        }
        Message = $e.Message -replace '\s+', ' ' | ForEach-Object { $_.Substring(0, [Math]::Min($_.Length, 800)) }
    }
}
$results | ConvertTo-Json -Depth 2 -Compress
""", timeout=90)

    # ── Brute force özeti: Kısa sürede aynı kullanıcıya çok sayıda 4625 ───────
    logs["brute_force_summary"] = run_powershell(r"""
$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4625;
    StartTime=(Get-Date).AddHours(-24)
} -MaxEvents 1000 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '{}'; exit }
$grouped = $events | ForEach-Object {
    try { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text' }
    catch { $null }
} | Where-Object {$_ -ne $null} |
Group-Object | Sort-Object Count -Descending | Select-Object -First 20 |
ForEach-Object {
    [PSCustomObject]@{ Username=$_.Name; FailCount=$_.Count; Period='Last 24h' }
}
$grouped | ConvertTo-Json -Compress
""", timeout=60)

    # ── 4698/4702 Scheduled task oluşturma/güncelleme (persistence) ───────────
    logs["scheduled_task_changes"] = run_powershell(r"""
$ids = @(4698,4699,4700,4701,4702)
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids} -MaxEvents 50 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$idDesc = @{4698='Task created';4699='Task deleted';4700='Task enabled';4701='Task disabled';4702='Task updated'}
$results = foreach ($e in $events) {
    try {
        $xml = [xml]$e.ToXml()
        $td = $xml.Event.EventData.Data
        [PSCustomObject]@{
            TimeCreated  = $e.TimeCreated.ToString('o')
            EventID      = $e.Id
            Description  = $idDesc[$e.Id]
            SubjectUser  = ($td | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
            TaskName     = ($td | Where-Object {$_.Name -eq 'TaskName'}).'#text'
            TaskContent  = ($td | Where-Object {$_.Name -eq 'TaskContentNew'}).'#text' |
                           ForEach-Object { if ($_) { $_.Substring(0, [Math]::Min($_.Length, 500)) } }
        }
    } catch { $null }
}
$results | Where-Object {$_ -ne $null} | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    # ── Audit policy kontrolü — hangi event'ler loglanıyor? ───────────────────
    logs["audit_policy"] = run_cmd("auditpol /get /category:*", timeout=30)

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

    # ── Açık dosyalar — process başına DLL/module dışı handle'lar ─────────────
    # openfiles /query sadece network share'leri gösterir, yerel için
    # process'lerin handles'ını PowerShell ile topluyoruz
    artifacts["open_files_network"] = run_cmd("openfiles /query /fo csv 2>nul", timeout=15)

    # Şu an yazılan/değiştirilen dosyalar — son 5 dakikada değişenler
    artifacts["recently_written_files"] = run_powershell("""\
$cutoff = (Get-Date).AddMinutes(-5)
$dirs = @(
    $env:TEMP, $env:TMP, 'C:\\Windows\\Temp',
    "$env:APPDATA", "$env:LOCALAPPDATA",
    "$env:USERPROFILE\\Downloads", "$env:USERPROFILE\\Desktop",
    'C:\\Windows\\System32', 'C:\\ProgramData'
)
$results = @()
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir -ErrorAction SilentlyContinue)) { continue }
    try {
        $results += Get-ChildItem $dir -File -ErrorAction SilentlyContinue |
            Where-Object {$_.LastWriteTime -gt $cutoff} |
            Select-Object FullName, LastWriteTime, Length,
            @{N='Hash';E={(Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash}},
            @{N='Dir';E={$dir}}
    } catch {}
}
$results | Sort-Object LastWriteTime -Descending | Select-Object -First 100 |
ConvertTo-Json -Compress
""", timeout=60)

    # Process başına açık dosya handle'ları — en aktif 20 process
    artifacts["process_open_handles"] = run_powershell("""\
Get-Process | Sort-Object Handles -Descending | Select-Object -First 20 |
Select-Object ProcessName, Id, Handles, WorkingSet,
@{N='Modules';E={try{$_.Modules.Count}catch{0}}},
@{N='Threads';E={$_.Threads.Count}},
Path |
ConvertTo-Json -Compress
""", timeout=30)

    return artifacts


# ─────────────────────────────────────────────
# 7. BROWSER
# ─────────────────────────────────────────────
def collect_browser_artifacts():
    import sqlite3 as _sql3
    import shutil   as _shutil
    import tempfile as _tmpfile

    browsers = {}
    up = os.environ.get("USERPROFILE", "")
    la = os.environ.get("LOCALAPPDATA", "")

    chrome_paths = {
        "history":    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History"),
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
                result[artifact] = {
                    "path":          path,
                    "exists":        True,
                    "size_bytes":    stat.st_size,
                    "last_modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                }
            else:
                result[artifact] = {"path": path, "exists": False}
        return result

    browsers["chrome"] = check_browser_files("Chrome", chrome_paths)
    browsers["edge"]   = check_browser_files("Edge",   edge_paths)
    browsers["firefox_profile_exists"] = os.path.exists(firefox_profile)

    # ── Chrome/Edge History SQLite — kopyala-oku ─────────────────────────────
    def read_browser_history(db_path, browser_name):
        """History SQLite'tan son 100 URL + gizli frame tespiti."""
        out = {"browser": browser_name, "urls": [], "hidden_visits": [], "error": None}
        if not os.path.exists(db_path):
            out["error"] = f"{browser_name} History bulunamadı"
            return out
        tmp = None
        try:
            tmp = _tmpfile.mktemp(suffix=".db")
            _shutil.copy2(db_path, tmp)
            conn = _sql3.connect(tmp)
            conn.row_factory = _sql3.Row
            cur = conn.cursor()

            # Son 100 URL
            cur.execute("""
                SELECT url, title, visit_count, last_visit_time,
                       typed_count, hidden
                FROM urls
                ORDER BY last_visit_time DESC
                LIMIT 100
            """)
            for row in cur.fetchall():
                # Chrome timestamp: microseconds since 1601-01-01
                ts = None
                if row["last_visit_time"]:
                    try:
                        epoch = (row["last_visit_time"] - 11644473600000000) / 1e6
                        ts = datetime.datetime.fromtimestamp(epoch).isoformat()
                    except Exception:
                        pass
                out["urls"].append({
                    "url":         row["url"],
                    "title":       row["title"],
                    "visit_count": row["visit_count"],
                    "last_visit":  ts,
                    "typed":       bool(row["typed_count"]),
                    "hidden":      bool(row["hidden"])
                })

            # Gizli/arka plan ziyaretler — transition type analizi
            # transition & 0xFF: 0=LINK, 1=TYPED, 2=AUTO_BOOKMARK, 4=AUTO_SUBFRAME
            # 3=MANUAL_SUBFRAME, 5=GENERATED, 7=START_PAGE, 8=FORM_SUBMIT, 9=RELOAD
            # Şüpheli: AUTO_SUBFRAME(4), MANUAL_SUBFRAME(3) — iframe/redirect
            try:
                cur.execute("""
                    SELECT u.url, u.title, v.visit_time, v.transition
                    FROM visits v
                    JOIN urls u ON v.url = u.id
                    WHERE (v.transition & 255) IN (3, 4)
                    ORDER BY v.visit_time DESC
                    LIMIT 50
                """)
                for row in cur.fetchall():
                    ts = None
                    if row["visit_time"]:
                        try:
                            epoch = (row["visit_time"] - 11644473600000000) / 1e6
                            ts = datetime.datetime.fromtimestamp(epoch).isoformat()
                        except Exception:
                            pass
                    t_type = row["transition"] & 0xFF
                    out["hidden_visits"].append({
                        "url":             row["url"],
                        "title":           row["title"],
                        "visit_time":      ts,
                        "transition_type": t_type,
                        "type_name":       "AUTO_SUBFRAME" if t_type == 4 else "MANUAL_SUBFRAME",
                        "flag":            "⚠ Gizli iframe/redirect — zararlı olabilir",
                        "severity":        "MEDIUM"
                    })
            except Exception:
                pass

            conn.close()
        except Exception as e:
            out["error"] = str(e)
        finally:
            if tmp:
                try:
                    os.remove(tmp)
                except Exception:
                    pass
        return out

    browsers["chrome_history"] = read_browser_history(chrome_paths["history"], "Chrome")
    browsers["edge_history"]   = read_browser_history(edge_paths["history"],   "Edge")

    browsers["chrome_extensions"] = run_powershell("""\
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

    browsers["ie_history_note"]     = "IE index.dat legacy format. Modern Edge uses SQLite."
    browsers["ps_download_history"] = run_powershell("""\
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
@{N='Triggers';E={($_.Triggers | ForEach-Object {$_.CimClass.CimClassName}) -join '; '}},
@{N='LastRunTime';E={$_.LastRunTime}},
@{N='LastTaskResult';E={$_.LastTaskResult}} |
ConvertTo-Json -Depth 3
""", timeout=60)

    # Son 30 günde oluşturulan/değiştirilen task'lar — highlight için ayrı
    data["recent_tasks_30d"] = run_powershell("""\
$cutoff  = (Get-Date).AddDays(-30)
$taskDir = 'C:\\Windows\\System32\\Tasks'
$results = @()

# Yöntem 1: System32\\Tasks altındaki XML dosyaları (en güvenilir)
if (Test-Path $taskDir) {
    Get-ChildItem $taskDir -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt $cutoff -or $_.CreationTime -gt $cutoff } |
    ForEach-Object {
        try {
            $xml      = [xml](Get-Content $_.FullName -Raw -ErrorAction Stop)
            $regDate  = $xml.Task.RegistrationInfo.Date
            $author   = $xml.Task.RegistrationInfo.Author
            $desc     = $xml.Task.RegistrationInfo.Description
            $actions  = ($xml.Task.Actions.Exec | ForEach-Object {
                            "$($_.Command) $($_.Arguments)"
                        }) -join '; '
            # Tarih: XML'den varsa al, yoksa dosya tarihini kullan
            $useDate  = if ($regDate) { try { [datetime]::Parse($regDate) } catch { $_.LastWriteTime } } else { $_.LastWriteTime }
            $results += [PSCustomObject]@{
                Name        = $_.BaseName
                Path        = $_.FullName.Replace($taskDir,'')
                Date        = $useDate.ToString('o')
                Author      = $author
                Description = $desc
                Actions     = $actions
                FileModified= $_.LastWriteTime.ToString('o')
                FileCreated = $_.CreationTime.ToString('o')
                FlagRecent  = $true
            }
        } catch {}
    }
}

# Yöntem 2: Yedek — Export-ScheduledTask (Yöntem 1 boşsa)
if ($results.Count -eq 0) {
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            $lastReg = if ($info.LastTaskResult -ne $null) { $info.LastRunTime } else { $null }
            # Task'ın XML dosya tarihi ile karşılaştır
            $taskFile = Join-Path $taskDir ($_.TaskPath.TrimStart('\\') + $_.TaskName)
            $fileMod  = if (Test-Path $taskFile) { (Get-Item $taskFile).LastWriteTime } else { $null }
            if ($fileMod -and $fileMod -gt $cutoff) {
                $results += [PSCustomObject]@{
                    Name        = $_.TaskName
                    Path        = $_.TaskPath
                    Date        = $fileMod.ToString('o')
                    Author      = ''
                    Description = ''
                    Actions     = ($_.Actions | ForEach-Object {"$($_.Execute) $($_.Arguments)"}) -join '; '
                    FileModified= $fileMod.ToString('o')
                    FlagRecent  = $true
                }
            }
        } catch {}
    }
}

if ($results.Count -eq 0) { Write-Output '[]' }
else { $results | Sort-Object Date -Descending | ConvertTo-Json -Depth 2 -Compress }
""", timeout=90)
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
def _extract_hashes_from_results(result):
    """Toplanan process/service/filesystem verisinden SHA256 hash listesi çıkarır."""
    hashes = []
    seen   = set()

    def _add(h, name, path, source):
        h = (h or "").upper().strip()
        if h and h not in ("N/A", "HASH_ERROR", "") and len(h) == 64 and h not in seen:
            seen.add(h)
            hashes.append({"hash": h, "name": name, "path": path or "unknown", "source": source})

    def _parse_json(raw, name_key, path_key, source):
        if not isinstance(raw, str) or not raw:
            return
        if "[ERROR]" in raw or "[TIMEOUT]" in raw:
            return
        try:
            items = json.loads(raw)
            if isinstance(items, dict):
                items = [items]
            for item in items:
                _add(item.get("Hash"), item.get(name_key, "unknown"), item.get(path_key), source)
        except Exception:
            pass

    # 1. Çalışan process'ler
    _parse_json(result.get("processes", {}).get("processes", ""), "ProcessName", "Path", "process")

    # 2. Çalışan servisler
    _parse_json(result.get("tasks_services", {}).get("services_running", ""), "Name", "PathName", "service")

    # 3. Startup items (tasks_services içinde)
    startup_raw = result.get("tasks_services", {}).get("startup_items", "")
    _parse_json(startup_raw, "Name", "Command", "startup")

    # 4. TEMP dizinlerindeki EXE/DLL'ler — filesystem modülünden
    temp_raw = result.get("filesystem", {}).get("temp_executables", "")
    _parse_json(temp_raw, "FullName", "FullName", "temp_file")

    # 5. Downloads dizinindeki EXE'ler — browser modülünden
    dl_raw = result.get("browsers", {}).get("ps_download_history", "")
    _parse_json(dl_raw, "Name", "Name", "download_file")

    # 6. Scheduled task binary'leri — task action'lardan path çıkar
    tasks_raw = result.get("tasks_services", {}).get("scheduled_tasks", "")
    if isinstance(tasks_raw, str) and tasks_raw and "[ERROR]" not in tasks_raw:
        try:
            tasks = json.loads(tasks_raw)
            if isinstance(tasks, dict):
                tasks = [tasks]
            for task in tasks:
                actions = task.get("Actions", "") or ""
                # Actions field'ındaki EXE path'lerini hash'le
                for token in actions.split(";"):
                    token = token.strip()
                    if token and os.path.isfile(token.split()[0]):
                        try:
                            fp = token.split()[0]
                            h  = hashlib.sha256(open(fp, 'rb').read()).hexdigest()
                            _add(h, os.path.basename(fp), fp, "scheduled_task")
                        except Exception:
                            pass
        except Exception:
            pass

    # 7. Non-standard path servis binary'leri — disk'ten hash al
    susp_svc_raw = result.get("tasks_services", {}).get("services_suspicious_paths", "")
    if isinstance(susp_svc_raw, str) and susp_svc_raw and "[ERROR]" not in susp_svc_raw:
        try:
            svcs = json.loads(susp_svc_raw)
            if isinstance(svcs, dict):
                svcs = [svcs]
            for svc in svcs:
                raw_path = (svc.get("PathName") or "").strip().strip('"').split()[0]
                if raw_path and os.path.isfile(raw_path):
                    try:
                        h = hashlib.sha256(open(raw_path, 'rb').read(10*1024*1024)).hexdigest()
                        _add(h, svc.get("Name", "unknown"), raw_path, "suspicious_service")
                    except Exception:
                        pass
        except Exception:
            pass

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
            pid     = proc.get("ProcessId")
            ppid    = proc.get("ParentProcessId")

            # Tool'un kendi process'lerini filtrele
            if _is_tool_process(pid, ppid, cmdline):
                continue

            if pname in PATTERNS:
                for pattern, desc in PATTERNS[pname]:
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        findings.append({
                            "process":     proc.get("Name"),
                            "pid":         pid,
                            "ppid":        ppid,
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
    """
    YARA taraması — yara-python veya yara-x ile çalışır.
    İkisi de yoksa sessizce atlanır (EXE çalışmaya devam eder).

    Build önceliği:
      1. yara-x   → pip install yara-x   (pre-built, C++ gerektirmez)
      2. yara-python → pip install yara-python (C++ Build Tools gerekir)
    """
    results = {
        "yara_available": False, "backend": None,
        "rules_loaded": 0, "files_scanned": 0,
        "findings": [], "errors": []
    }

    # ── Backend tespiti ────────────────────────────────────────────────────────
    _yara       = None
    _yarax      = None
    _backend    = None

    try:
        import yara as _yara_mod
        _yara    = _yara_mod
        _backend = "yara-python"
    except ImportError:
        pass

    if _yara is None:
        try:
            import yara_x as _yarax_mod
            _yarax   = _yarax_mod
            _backend = "yara-x"
        except ImportError:
            pass

    if _backend is None:
        results["error"] = (
            "YARA kütüphanesi bulunamadı. "
            "EXE build için: 'pip install yara-x' (C++ gerektirmez). "
            "Tam destek için: 'pip install yara-python' (C++ Build Tools gerekir)."
        )
        return results

    results["yara_available"] = True
    results["backend"]        = _backend

    # ── Kural dizini ──────────────────────────────────────────────────────────
    if not rules_dir:
        rules_dir = _find_data_dir("yara_rules")
    if not rules_dir or not os.path.exists(rules_dir):
        results["error"] = "YARA rules dizini bulunamadı"
        return results

    # ── Kuralları derle ───────────────────────────────────────────────────────
    compiled_rules = []  # [(rule_filename, compiled_obj)]

    for rf in os.listdir(rules_dir):
        if not rf.lower().endswith(('.yar', '.yara')):
            continue
        rpath = os.path.join(rules_dir, rf)
        try:
            if _backend == "yara-python":
                compiled_rules.append((rf, _yara.compile(filepath=rpath)))
            else:
                # yara-x: Rules nesnesi string kaynak kabul eder
                with open(rpath, 'r', encoding='utf-8', errors='replace') as f:
                    source = f.read()
                compiled_rules.append((rf, _yarax.compile(source)))
            results["rules_loaded"] += 1
        except Exception as e:
            results["errors"].append(f"Derleme hatası {rf}: {str(e)[:120]}")

    if not compiled_rules:
        results["error"] = "Hiç YARA kuralı derlenemedi"
        return results

    # ── Tarama hedefleri ──────────────────────────────────────────────────────
    scan_targets  = []
    seen_targets  = set()
    EXE_EXTS      = {'.exe','.dll','.ps1','.vbs','.js','.bat','.scr','.com','.hta','.jar','.cmd'}
    SCRIPT_EXTS   = {'.ps1','.vbs','.js','.bat','.hta','.cmd','.py','.rb'}
    ALL_EXTS      = EXE_EXTS | SCRIPT_EXTS

    def _add(path):
        if path and path not in seen_targets and os.path.isfile(path):
            seen_targets.add(path)
            scan_targets.append(path)

    def _scan_dir(d, exts, recurse=False, max_files=200):
        if not d or not os.path.exists(d):
            return
        try:
            if recurse:
                count = 0
                for root, dirs, files in os.walk(d):
                    dirs[:] = [x for x in dirs if x.lower() not in
                                ('node_modules','.git','__pycache__','vendor','.svn')]
                    for f in files:
                        if os.path.splitext(f)[1].lower() in exts:
                            _add(os.path.join(root, f))
                            count += 1
                            if count >= max_files:
                                return
            else:
                for f in os.listdir(d):
                    if os.path.splitext(f)[1].lower() in exts:
                        _add(os.path.join(d, f))
        except Exception:
            pass

    up   = os.environ.get("USERPROFILE", "")
    app  = os.environ.get("APPDATA", "")
    lapp = os.environ.get("LOCALAPPDATA", "")
    tmp  = os.environ.get("TEMP", "")
    tmp2 = os.environ.get("TMP", "")

    # 1. TEMP dizinleri — en riskli alan
    for tdir in [tmp, tmp2, r"C:\Windows\Temp"]:
        _scan_dir(tdir, ALL_EXTS)

    # 2. System32 / SysWOW64 — son 7 günde değişenler
    cutoff = datetime.datetime.now() - datetime.timedelta(days=7)
    for sdir in [r"C:\Windows\System32", r"C:\Windows\SysWOW64"]:
        if os.path.exists(sdir):
            try:
                for f in os.listdir(sdir):
                    fp = os.path.join(sdir, f)
                    if os.path.isfile(fp) and os.path.splitext(f)[1].lower() in ALL_EXTS:
                        try:
                            if datetime.datetime.fromtimestamp(os.path.getmtime(fp)) > cutoff:
                                _add(fp)
                        except Exception:
                            pass
            except Exception:
                pass

    # 3. Web dizinleri
    for web_dir in [r"C:\inetpub\wwwroot", r"C:\xampp\htdocs",
                    r"C:\wamp\www", r"C:\wamp64\www", r"C:\nginx\html"]:
        _scan_dir(web_dir, {'.php','.asp','.aspx','.jsp','.ps1','.bat','.exe','.dll'},
                  recurse=True, max_files=100)

    # 4. Downloads
    _scan_dir(os.path.join(up, "Downloads"), ALL_EXTS)

    # 5. Desktop
    _scan_dir(os.path.join(up, "Desktop"), ALL_EXTS)

    # 6. AppData\Roaming — yüzeysel (RAT'lar buraya kurulur)
    _scan_dir(app, EXE_EXTS, recurse=False)
    # Alt klasörler — 1 seviye derine in
    if os.path.exists(app):
        try:
            for sub in os.listdir(app):
                subpath = os.path.join(app, sub)
                if os.path.isdir(subpath):
                    _scan_dir(subpath, EXE_EXTS, recurse=False)
        except Exception:
            pass

    # 7. LocalAppData yüzeysel
    _scan_dir(lapp, EXE_EXTS, recurse=False)

    # 8. Startup dizinleri — persistence
    startups = [
        os.path.join(app, r"Microsoft\Windows\Start Menu\Programs\Startup"),
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    ]
    for sd in startups:
        _scan_dir(sd, ALL_EXTS)

    # 9. ProgramData yüzeysel
    _scan_dir(r"C:\ProgramData", EXE_EXTS, recurse=False)

    # 10. Non-standard path'teki servis binary'leri
    try:
        import subprocess as _sp2
        svc_raw = _sp2.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command",
             "Get-WmiObject Win32_Service | Where-Object {$_.PathName -notmatch "
             "'System32|SysWOW64|Program Files|Windows' -and $_.PathName -ne $null} | "
             "Select-Object -ExpandProperty PathName"],
            capture_output=True, text=True, timeout=20
        )
        for line in svc_raw.stdout.splitlines():
            # Path'i temizle (tırnak, parametre vb.)
            p = line.strip().strip('"').split()[0] if line.strip() else ""
            if p:
                _add(p)
    except Exception:
        pass

    results["scan_dirs_checked"] = len(seen_targets)

    # ── Tara ──────────────────────────────────────────────────────────────────
    for fpath in scan_targets[:500]:
        if not os.path.isfile(fpath):
            continue
        results["files_scanned"] += 1

        for rule_file, compiled in compiled_rules:
            try:
                if _backend == "yara-python":
                    matches = compiled.match(fpath, timeout=10)
                    if matches:
                        stat = os.stat(fpath)
                        results["findings"].append({
                            "file":          fpath,
                            "rule_file":     rule_file,
                            "matched_rules": [m.rule for m in matches],
                            "tags":          [t for m in matches for t in m.tags],
                            "size_bytes":    stat.st_size,
                            "last_modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "severity":      "HIGH"
                        })
                else:
                    with open(fpath, 'rb') as fh:
                        data = fh.read(2 * 1024 * 1024)
                    scan_result = compiled.scan(data)
                    matching = list(scan_result.matching_rules)
                    if matching:
                        stat = os.stat(fpath)
                        results["findings"].append({
                            "file":          fpath,
                            "rule_file":     rule_file,
                            "matched_rules": [r.identifier for r in matching],
                            "tags":          [t for r in matching for t in r.tags],
                            "size_bytes":    stat.st_size,
                            "last_modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "severity":      "HIGH"
                        })
            except Exception as e:
                results["errors"].append(f"{os.path.basename(fpath)}: {str(e)[:80]}")

    return results


# ─────────────────────────────────────────────
# 16. PARENT-CHILD ANOMALI ANALİZİ
# ─────────────────────────────────────────────
def collect_parent_child_anomalies(processes_result):
    """
    Bilinen meşru parent-child ilişkilerinden sapmaları tespit eder.
    Örnek: winword.exe → powershell.exe (macro saldırısı)
            explorer.exe → svchost.exe (hollowing)
            svchost.exe → cmd.exe (lateral movement)
    """

    # Beklenen parent → child haritası
    # Format: {child: [izin verilen parentlar]}
    EXPECTED_PARENTS = {
        "smss.exe":        ["system", "smss.exe"],
        "csrss.exe":       ["smss.exe"],
        "wininit.exe":     ["smss.exe"],
        "winlogon.exe":    ["smss.exe"],
        "services.exe":    ["wininit.exe"],
        "lsass.exe":       ["wininit.exe"],
        "svchost.exe":     ["services.exe", "msiexec.exe"],
        "taskhost.exe":    ["services.exe", "svchost.exe"],
        "taskhostw.exe":   ["services.exe", "svchost.exe"],
        "explorer.exe":    ["userinit.exe", "winlogon.exe"],
        "userinit.exe":    ["winlogon.exe"],
        "spoolsv.exe":     ["services.exe"],
        "searchindexer.exe": ["services.exe"],
    }

    # Bu parent'lardan cmd/powershell/wscript çıkması şüpheli
    SUSPICIOUS_SHELL_PARENTS = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "acrord32.exe", "acrobat.exe", "mspub.exe", "visio.exe",
        "onenote.exe", "msaccess.exe", "eqnedt32.exe",
        "iexplore.exe", "chrome.exe", "firefox.exe", "msedge.exe",
        "java.exe", "javaw.exe", "wscript.exe", "mshta.exe",
    }

    SHELL_PROCESSES = {
        "cmd.exe", "powershell.exe", "pwsh.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        "sh.exe", "bash.exe",
    }

    # Kritik process'lerin birden fazla çalışması şüpheli
    SINGLE_INSTANCE = {
        "lsass.exe", "wininit.exe", "services.exe",
        "smss.exe", "csrss.exe",
    }

    findings   = []
    proc_map   = {}   # pid → process bilgisi
    name_count = {}   # name → count

    raw = processes_result.get("processes", "")
    if not raw or "[ERROR]" in raw or "[TIMEOUT]" in raw:
        return {"findings": [], "error": "Process verisi alınamadı"}

    try:
        procs = json.loads(raw)
        if isinstance(procs, dict):
            procs = [procs]
    except Exception as e:
        return {"findings": [], "error": str(e)}

    # PID haritası kur + sayaç
    for p in procs:
        pid  = p.get("PID")
        name = (p.get("ProcessName") or "").lower()
        if pid:
            proc_map[int(pid)] = p
        name_count[name] = name_count.get(name, 0) + 1

    for p in procs:
        pname  = (p.get("ProcessName") or "").lower()
        ppid   = p.get("PPID")
        pid    = p.get("PID")
        path   = (p.get("Path") or "").lower()
        cmdline_pc = (p.get("CommandLine") or "")

        # Tool'un kendi process'lerini atla
        if _is_tool_process(pid, ppid, cmdline_pc):
            continue

        parent = proc_map.get(int(ppid)) if ppid else None
        parent_name = (parent.get("ProcessName") or "unknown").lower() if parent else "unknown"

        # ── Kural 1: Office/Browser → shell spawn ─────────────────────────────
        if pname in SHELL_PROCESSES and parent_name in SUSPICIOUS_SHELL_PARENTS:
            findings.append({
                "type":       "SUSPICIOUS_PARENT_CHILD",
                "severity":   "CRITICAL",
                "detection":  f"Office/browser spawned shell: {parent_name} → {pname}",
                "child":      pname,
                "child_pid":  pid,
                "parent":     parent_name,
                "parent_pid": ppid,
                "path":       path,
                "note":       "Macro saldırısı veya drive-by exploit indikatörü"
            })

        # ── Kural 2: Kritik sistem process'i beklenmedik parent'tan ──────────
        if pname in EXPECTED_PARENTS:
            allowed = EXPECTED_PARENTS[pname]
            if parent_name not in allowed and parent_name != "unknown":
                findings.append({
                    "type":       "UNEXPECTED_PARENT",
                    "severity":   "HIGH",
                    "detection":  f"Unexpected parent for {pname}: {parent_name}",
                    "child":      pname,
                    "child_pid":  pid,
                    "parent":     parent_name,
                    "parent_pid": ppid,
                    "path":       path,
                    "note":       "Process hollowing veya injection indikatörü olabilir"
                })

        # ── Kural 3: Kritik process'in birden fazla instance'ı ───────────────
        if pname in SINGLE_INSTANCE and name_count.get(pname, 0) > 1:
            findings.append({
                "type":      "MULTIPLE_INSTANCES",
                "severity":  "HIGH",
                "detection": f"{pname} has {name_count[pname]} instances (expected: 1)",
                "process":   pname,
                "pid":       pid,
                "path":      path,
                "note":      "Process masquerade veya hollowing indikatörü"
            })

        # ── Kural 4: Sistem process'i sistem dışı path'ten çalışıyor ─────────
        SYSTEM_PROCS = {
            "svchost.exe", "lsass.exe", "services.exe", "wininit.exe",
            "csrss.exe", "smss.exe", "explorer.exe", "taskhost.exe",
            "taskhostw.exe", "spoolsv.exe", "winlogon.exe"
        }
        if pname in SYSTEM_PROCS and path:
            expected_paths = ["c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\"]
            if not any(path.startswith(ep) for ep in expected_paths):
                findings.append({
                    "type":      "MASQUERADED_PROCESS",
                    "severity":  "CRITICAL",
                    "detection": f"System process running from non-system path: {pname}",
                    "process":   pname,
                    "pid":       pid,
                    "path":      path,
                    "note":      "Malware masquerading as system process"
                })

        # ── Kural 5: svchost.exe -k parametresi olmadan çalışıyor ────────────
        if pname == "svchost.exe":
            cmdline = (p.get("CommandLine") or "").lower()
            if cmdline and "-k" not in cmdline:
                findings.append({
                    "type":      "SVCHOST_MISSING_K_FLAG",
                    "severity":  "HIGH",
                    "detection": "svchost.exe running without -k flag",
                    "process":   pname,
                    "pid":       pid,
                    "cmdline":   cmdline[:300],
                    "path":      path,
                    "note":      "Meşru svchost her zaman -k parametresiyle çalışır"
                })

    return {
        "findings":     findings,
        "total_found":  len(findings),
        "processes_analyzed": len(procs)
    }


# ─────────────────────────────────────────────
# 17. İMZASIZ PROCESS TESPİTİ
# ─────────────────────────────────────────────
def collect_unsigned_processes():
    """
    Çalışan process'lerin Authenticode imzalarını kontrol eder.
    İmzasız veya imzası geçersiz olan process'leri raporlar.
    Microsoft/Windows imzalı olanlar gürültüyü azaltmak için filtrelenir.
    """
    raw = run_powershell(r"""
$procs = Get-Process | Where-Object {$_.Path -ne $null} |
    Select-Object -Property Id, ProcessName, Path -Unique

$results = foreach ($p in $procs) {
    try {
        $sig = Get-AuthenticodeSignature -FilePath $p.Path -ErrorAction Stop
        # Temiz ve Microsoft imzalı olanları atla
        if ($sig.Status -eq 'Valid' -and
            ($sig.SignerCertificate.Subject -match 'Microsoft|Windows')) {
            continue
        }
        [PSCustomObject]@{
            PID           = $p.Id
            ProcessName   = $p.ProcessName
            Path          = $p.Path
            SignatureStatus = $sig.Status.ToString()
            SignerSubject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'No certificate' }
            SignerThumb   = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { 'N/A' }
            IsOSBinary    = $sig.IsOSBinary
        }
    } catch {
        [PSCustomObject]@{
            PID             = $p.Id
            ProcessName     = $p.ProcessName
            Path            = $p.Path
            SignatureStatus = 'ERROR'
            SignerSubject   = $_.Exception.Message
            SignerThumb     = 'N/A'
            IsOSBinary      = $false
        }
    }
}

# Sadece şüpheli olanları döndür
$suspicious = $results | Where-Object {
    $_.SignatureStatus -in @('NotSigned','HashMismatch','NotTrusted','UnknownError','ERROR') -or
    ($_.SignatureStatus -eq 'Valid' -and $_.IsOSBinary -eq $false -and
     $_.Path -match 'Temp|AppData|Users.*Downloads|Public')
}

if (-not $suspicious) { Write-Output '[]'; exit }
$suspicious | ConvertTo-Json -Depth 2 -Compress
""", timeout=120)

    findings = []
    error    = None

    try:
        if raw and "[ERROR]" not in raw and "[TIMEOUT]" not in raw and raw != "[]":
            items = json.loads(raw)
            if isinstance(items, dict):
                items = [items]
            for item in items:
                # Tool'un kendi process'lerini atla
                item_pid = item.get("PID")
                if item_pid and item_pid in _TOOL_PIDS:
                    continue
                status = item.get("SignatureStatus", "")
                severity = "CRITICAL" if status in ("HashMismatch", "NotTrusted") else "HIGH"
                findings.append({
                    "pid":              item.get("PID"),
                    "process":          item.get("ProcessName"),
                    "path":             item.get("Path"),
                    "signature_status": status,
                    "signer":           item.get("SignerSubject"),
                    "severity":         severity,
                    "note": {
                        "NotSigned":    "İmzasız EXE — meşru yazılım olabilir ama şüpheli path'lerde kritik",
                        "HashMismatch": "Hash uyuşmazlığı — dosya değiştirilmiş olabilir (tamper!)",
                        "NotTrusted":   "Güvenilmeyen imza — self-signed veya revoke edilmiş sertifika",
                        "ERROR":        "İmza okunamadı"
                    }.get(status, "İncelenmeli")
                })
    except Exception as e:
        error = str(e)

    return {
        "findings":    findings,
        "total_found": len(findings),
        "error":       error
    }


# ─────────────────────────────────────────────
# 18. NETWORK IOC KARŞILAŞTIRMA
# ─────────────────────────────────────────────
def collect_network_ioc(network_result):
    """
    Aktif ağ bağlantılarını bilinen C2/kötü IP ve domain listesiyle karşılaştırır.
    ioc/network_ioc.txt dosyasındaki IP ve domain'leri kullanır.
    """
    results = {
        "matches":      [],
        "ioc_ips":      0,
        "ioc_domains":  0,
        "checked_connections": 0,
        "error":        None
    }

    ioc_dir = _find_data_dir("ioc")
    if not ioc_dir:
        results["error"] = "IOC dizini bulunamadı"
        return results

    ioc_file = os.path.join(ioc_dir, "network_ioc.txt")
    if not os.path.exists(ioc_file):
        results["error"] = "network_ioc.txt bulunamadı (ioc/ klasörüne ekleyin)"
        return results

    # IOC listesini yükle
    bad_ips     = set()
    bad_domains = set()
    try:
        with open(ioc_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('IP:'):
                    bad_ips.add(line[3:].strip().lower())
                elif line.startswith('DOMAIN:'):
                    bad_domains.add(line[7:].strip().lower())
                else:
                    # Prefix olmadan — IP mi domain mi otomatik belirle
                    import re as _re
                    if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                        bad_ips.add(line.lower())
                    else:
                        bad_domains.add(line.lower())
    except Exception as e:
        results["error"] = f"IOC dosyası okunamadı: {e}"
        return results

    results["ioc_ips"]     = len(bad_ips)
    results["ioc_domains"] = len(bad_domains)

    if not bad_ips and not bad_domains:
        results["error"] = "IOC listesi boş"
        return results

    # ── Bağlantıları topla ────────────────────────────────────────────────────
    all_conns   = []
    checked_ips = set()

    # 1. PowerShell JSON çıktıları (established + listening)
    for raw in [network_result.get("established_connections",""),
                network_result.get("listening_ports","")]:
        if not raw or "[ERROR]" in raw or "[TIMEOUT]" in raw:
            continue
        try:
            items = json.loads(raw)
            if isinstance(items, dict):
                items = [items]
            all_conns.extend(items)
        except Exception:
            continue

    # 2. netstat -anob çıktısını da parse et (daha kapsamlı, UDP dahil)
    netstat_raw = network_result.get("netstat", "")
    if netstat_raw and "[ERROR]" not in netstat_raw and "[TIMEOUT]" not in netstat_raw:
        for line in netstat_raw.splitlines():
            parts = line.split()
            # TCP/UDP satırları: Proto  LocalAddr  ForeignAddr  State  [PID]
            if len(parts) >= 3 and parts[0].upper() in ("TCP", "UDP", "TCP6", "UDP6"):
                foreign = parts[2] if len(parts) > 2 else ""
                if foreign and foreign != "*:*" and ":" in foreign:
                    # IPv4: 1.2.3.4:port  IPv6: [::]:port
                    ip_part = foreign.rsplit(":", 1)[0].strip("[]")
                    if ip_part:
                        # JSON conn objesi formatına çevir
                        all_conns.append({
                            "RemoteAddress": ip_part,
                            "RemotePort":    foreign.rsplit(":", 1)[-1] if ":" in foreign else "",
                            "Process":       parts[-1] if parts[-1].isdigit() else None,
                            "State":         parts[3] if len(parts) > 3 else "UNKNOWN"
                        })

    results["checked_connections"] = len(all_conns)

    # DNS cache'de de kontrol et
    dns_raw = network_result.get("dns_cache", "")

    for conn in all_conns:
        remote_ip = (conn.get("RemoteAddress") or "").strip().lower()
        if not remote_ip or remote_ip in ("0.0.0.0", "::", "127.0.0.1", "::1", "*"):
            continue
        checked_ips.add(remote_ip)

        if remote_ip in bad_ips:
            results["matches"].append({
                "type":         "MALICIOUS_IP",
                "severity":     "CRITICAL",
                "remote_ip":    remote_ip,
                "remote_port":  conn.get("RemotePort"),
                "local_ip":     conn.get("LocalAddress"),
                "local_port":   conn.get("LocalPort"),
                "process":      conn.get("Process"),
                "pid":          conn.get("PID"),
                "state":        conn.get("State"),
                "note":         "Bilinen C2 / kötü amaçlı IP ile aktif bağlantı"
            })

    # DNS cache domain kontrolü
    if dns_raw and bad_domains:
        for domain in bad_domains:
            if domain in dns_raw.lower():
                results["matches"].append({
                    "type":     "MALICIOUS_DOMAIN",
                    "severity": "CRITICAL",
                    "domain":   domain,
                    "source":   "DNS cache",
                    "note":     "Bilinen kötü amaçlı domain DNS cache'inde bulundu"
                })

    return results


# ─────────────────────────────────────────────
# 19. HOLLOW PROCESS TESPİTİ
# ─────────────────────────────────────────────
def collect_hollow_process():
    """
    Process hollowing tespiti — disk'teki EXE ile bellekteki imaj arasındaki
    farklılıkları tespit eder. Kısmi tespit: kernel-level erişim olmadan
    tam memory dump analizi yapılamaz, ancak aşağıdaki indikatörler kullanılır:

    1. PATH farklılığı — process'in bildirdiği path ile gerçek path farklı
    2. Image path vs command line uyumsuzluğu
    3. Şüpheli bellek bölgeleri — RWX izinli anonim bellek
    """
    results = {
        "path_mismatches":       [],
        "rwx_memory_regions":    [],
        "cmdline_path_mismatch": [],
        "total_findings":        0,
        "error":                 None,
        "note": "Kernel driver olmadan tam hollowing tespiti yapılamaz. "
                "Bu kontroller indikatör düzeyindedir, kesin sonuç değildir."
    }

    # ── 1. Path uyumsuzluğu — WMI ExecutablePath vs Get-Process Path ─────────
    raw = run_powershell(r"""
$wmi = Get-WmiObject Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine
$psProcs = Get-Process | Select-Object Id, Path

$wmiMap = @{}
foreach ($w in $wmi) { if ($w.ProcessId) { $wmiMap[[int]$w.ProcessId] = $w } }

$results = foreach ($p in $psProcs) {
    $w = $wmiMap[[int]$p.Id]
    if (-not $w) { continue }

    $wmiPath = ($w.ExecutablePath -replace '\\\\','\\').ToLower().Trim().TrimEnd('\')
    $psPath  = ($p.Path -replace '\\\\','\\').ToLower().Trim().TrimEnd('\')

    if (-not $wmiPath -or -not $psPath) { continue }

    if ($wmiPath -ne $psPath) {
        $wmiFile = [System.IO.Path]::GetFileName($wmiPath)
        $psFile  = [System.IO.Path]::GetFileName($psPath)
        # Sadece dosya adı da farklıysa gerçek anomali
        if ($wmiFile -ne $psFile) {
            [PSCustomObject]@{
                PID        = $p.Id
                Name       = $w.Name
                WMI_Path   = $w.ExecutablePath
                PS_Path    = $p.Path
                CommandLine= $w.CommandLine
            }
        }
    }
}
if (-not $results) { Write-Output '[]'; exit }
$results | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    if raw and "[ERROR]" not in raw and "[TIMEOUT]" not in raw and raw != "[]":
        try:
            items = json.loads(raw)
            if isinstance(items, dict):
                items = [items]
            for item in items:
                h_pid = item.get("PID")
                if h_pid and h_pid in _TOOL_PIDS:
                    continue
                results["path_mismatches"].append({
                    "pid":         h_pid,
                    "name":        item.get("Name"),
                    "wmi_path":    item.get("WMI_Path"),
                    "ps_path":     item.get("PS_Path"),
                    "commandline": item.get("CommandLine", "")[:300],
                    "severity":    "HIGH",
                    "note":        "WMI ve Get-Process farklı path bildiriyor — hollowing indikatörü"
                })
        except Exception as e:
            results["error"] = f"Path mismatch parse: {e}"

    # ── 2. CommandLine içindeki EXE ile path uyumsuzluğu ─────────────────────
    raw2 = run_powershell(r"""
$procs = Get-WmiObject Win32_Process |
    Where-Object {$_.ExecutablePath -ne $null -and $_.CommandLine -ne $null} |
    Select-Object ProcessId, Name, ExecutablePath, CommandLine

$results = foreach ($p in $procs) {
    # CommandLine'dan ilk token'ı çıkar (EXE path)
    $cl = $p.CommandLine.Trim().TrimStart('"')
    $firstToken = ($cl -split '"')[0].Trim()
    if (-not $firstToken) {
        $firstToken = ($cl -split '\s+')[0]
    }
    $firstToken = $firstToken.ToLower().Trim('\\"')
    $exePath    = $p.ExecutablePath.ToLower()

    # Basit karşılaştırma: farklıysa ve her ikisi de path içeriyorsa
    if ($firstToken -match '\\' -and $exePath -and
        $firstToken -ne $exePath -and
        [System.IO.Path]::GetFileName($firstToken) -ne [System.IO.Path]::GetFileName($exePath)) {
        [PSCustomObject]@{
            PID         = $p.ProcessId
            Name        = $p.Name
            ExePath     = $p.ExecutablePath
            CmdLineExe  = $firstToken
            CommandLine = $p.CommandLine
        }
    }
}
if (-not $results) { Write-Output '[]'; exit }
$results | ConvertTo-Json -Depth 2 -Compress
""", timeout=60)

    if raw2 and "[ERROR]" not in raw2 and "[TIMEOUT]" not in raw2 and raw2 != "[]":
        try:
            items = json.loads(raw2)
            if isinstance(items, dict):
                items = [items]
            for item in items:
                cm_pid = item.get("PID")
                if cm_pid and cm_pid in _TOOL_PIDS:
                    continue
                results["cmdline_path_mismatch"].append({
                    "pid":          cm_pid,
                    "name":         item.get("Name"),
                    "exe_path":     item.get("ExePath"),
                    "cmdline_exe":  item.get("CmdLineExe"),
                    "commandline":  (item.get("CommandLine") or "")[:300],
                    "severity":     "HIGH",
                    "note":         "CommandLine'daki EXE adı ExecutablePath ile uyuşmuyor"
                })
        except Exception:
            pass

    # ── 3. RWX bellek bölgeleri — VirtualQueryEx seviyesinde kısmi kontrol ────
    # PowerShell'den tam VirtualQuery yapılamaz, ancak VMMap benzeri çıktılar
    # için sysinternals olmadan kısmi bilgi alınabilir.
    raw3 = run_powershell(r"""
# Injection'da sık kullanılan: execute izni olan anonim bellek bölgeleri
# Get-Process Modules ile eşleşmeyen bellek alanları şüpheli
$results = @()
$procs = Get-Process | Where-Object {$_.Id -gt 4} | Select-Object -First 50

foreach ($proc in $procs) {
    $mods = $null
    try { $mods = $proc.Modules } catch { continue }
    if (-not $mods) { continue }

    # Modülü olmayan ama bellek kullanan process'ler
    if ($mods.Count -eq 0 -and $proc.WorkingSet -gt 10MB) {
        $results += [PSCustomObject]@{
            PID     = $proc.Id
            Name    = $proc.ProcessName
            RAM_MB  = [math]::Round($proc.WorkingSet/1MB,1)
            Modules = 0
            Note    = 'No modules but significant memory usage'
        }
    }
}
if ($results.Count -eq 0) { Write-Output '[]'; exit }
$results | ConvertTo-Json -Compress
""", timeout=60)

    if raw3 and "[ERROR]" not in raw3 and "[TIMEOUT]" not in raw3 and raw3 != "[]":
        try:
            items = json.loads(raw3)
            if isinstance(items, dict):
                items = [items]
            for item in items:
                results["rwx_memory_regions"].append({
                    "pid":     item.get("PID"),
                    "name":    item.get("Name"),
                    "ram_mb":  item.get("RAM_MB"),
                    "modules": item.get("Modules"),
                    "severity":"MEDIUM",
                    "note":    item.get("Note", "Şüpheli bellek kullanımı")
                })
        except Exception:
            pass

    results["total_findings"] = (
        len(results["path_mismatches"]) +
        len(results["cmdline_path_mismatch"]) +
        len(results["rwx_memory_regions"])
    )

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

    # ── Tool'un child process'lerini PID filtresine ekle ──────────────────────
    # Tüm modüller çalışmadan önce bir kere snapshot al
    try:
        import subprocess as _sp
        _snap = _sp.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command",
             f"Get-WmiObject Win32_Process | Where-Object {{$_.ParentProcessId -eq {_TOOL_OWN_PID}}} | Select-Object -ExpandProperty ProcessId"],
            capture_output=True, text=True, timeout=10
        )
        for line in _snap.stdout.splitlines():
            line = line.strip()
            if line.isdigit():
                _TOOL_PIDS.add(int(line))
    except Exception:
        pass

    result = {
        "meta": {
            "tool":       "TEA Forensic Collector",
            "version":    "1.2.0",
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

    # Browser history'yi ayrı top-level key'e çıkar
    browsers = result.get("browsers", {})
    result["browser_history"] = {
        "chrome": browsers.get("chrome_history", {}),
        "edge":   browsers.get("edge_history",   {}),
    }

    # Recent tasks'ı ayrı top-level key'e çıkar
    result["recent_tasks"] = result.get("tasks_services", {}).get("recent_tasks_30d", [])

    # Active files'ı ayrı top-level key'e çıkar
    result["active_files"] = {
        "recently_written": result.get("filesystem", {}).get("recently_written_files", []),
        "open_handles":     result.get("filesystem", {}).get("process_open_handles", []),
        "open_network":     result.get("filesystem", {}).get("open_files_network", ""),
    }

    update("Building hash inventory...", 78)
    all_hashes = _extract_hashes_from_results(result)
    result["meta"]["total_hashes_collected"] = len(all_hashes)

    update("Parent-Child Anomaly Analysis...", 79)
    try:
        result["parent_child"] = collect_parent_child_anomalies(result.get("processes", {}))
    except Exception as e:
        result["parent_child"] = {"error": str(e)}
    if partial_ref is not None:
        partial_ref.update(result)

    update("Unsigned Process Detection...", 80)
    try:
        result["unsigned_processes"] = collect_unsigned_processes()
    except Exception as e:
        result["unsigned_processes"] = {"error": str(e)}
    if partial_ref is not None:
        partial_ref.update(result)

    update("Network IOC Comparison...", 81)
    try:
        result["network_ioc"] = collect_network_ioc(result.get("network", {}))
    except Exception as e:
        result["network_ioc"] = {"error": str(e)}
    if partial_ref is not None:
        partial_ref.update(result)

    update("Hollow Process Detection...", 82)
    try:
        result["hollow_process"] = collect_hollow_process()
    except Exception as e:
        result["hollow_process"] = {"error": str(e)}
    if partial_ref is not None:
        partial_ref.update(result)

    update("IOC Hash Comparison...", 83)
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
