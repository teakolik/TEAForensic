/*
    TEA Forensic Collector - YARA Rules
    Kaynak: Açık kaynak tehdit istihbaratı + özel kurallar
    Platform: Windows DFIR
*/

rule Mimikatz_Strings
{
    meta:
        description = "Mimikatz credential dumper"
        severity    = "CRITICAL"
        author      = "TEA Security"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii nocase
        $s2 = "lsadump::sam"            ascii nocase
        $s3 = "mimikatz"                ascii nocase
        $s4 = "benjamin@gentilkiwi.com" ascii
        $s5 = "privilege::debug"        ascii nocase
        $s6 = "kerberos::golden"        ascii nocase
        $s7 = "sekurlsa::wdigest"       ascii nocase
    condition:
        2 of them
}

rule Meterpreter_Indicators
{
    meta:
        description = "Metasploit Meterpreter payload"
        severity    = "CRITICAL"
        author      = "TEA Security"
    strings:
        $s1 = "meterpreter"                  ascii nocase
        $s2 = "stdapi_sys_process_execute"   ascii
        $s3 = "ReflectiveDll"               ascii
        $s4 = "METERPRETER_TRANSPORT_TCP"   ascii
        $s5 = "metsrv"                       ascii nocase
        $s6 = "meterupdate"                  ascii nocase
    condition:
        1 of them
}

rule CobaltStrike_Beacon
{
    meta:
        description = "Cobalt Strike beacon indicators"
        severity    = "CRITICAL"
        author      = "TEA Security"
    strings:
        $s1 = "ReflectiveLoader"   ascii
        $s2 = "beacon"             ascii nocase
        $s3 = "%08X-%04X-%04X"     ascii
        $pe  = { 4D 5A }
        // CS default sleep mask pattern
        $cs1 = { 69 6E 69 00 56 69 72 74 75 61 6C }
        // CS malleable profile artifact
        $cs2 = "Accept: */*\r\nContent-Type: application/octet-stream" ascii
    condition:
        $pe and (2 of ($s1, $s2, $s3, $cs1, $cs2))
}

rule PowerShell_Encoded_Command
{
    meta:
        description = "Obfuscated/encoded PowerShell command in file"
        severity    = "HIGH"
        author      = "TEA Security"
    strings:
        // Common base64 PowerShell payloads
        $b1 = "JABjAGwAaQBlAG4AdA"   ascii   // $client
        $b2 = "SQBFAFgA"             ascii   // IEX
        $b3 = "JABzAGUAcwBzAGkAbwBu" ascii   // $session
        $b4 = "cABvAHcAZQByAHMAaABlAGwAbA" ascii // powershell
        // Direct indicators
        $e1 = "powershell -e "       ascii nocase
        $e2 = "powershell -enc "     ascii nocase
        $e3 = "powershell -EncodedCommand" ascii nocase
        $e4 = "FromBase64String"     ascii nocase
        $e5 = "IEX(New-Object"       ascii nocase
        $e6 = "Invoke-Expression"    ascii nocase
    condition:
        2 of them
}

rule Webshell_PHP_Generic
{
    meta:
        description = "Generic PHP webshell patterns"
        severity    = "CRITICAL"
        author      = "TEA Security"
    strings:
        $php  = "<?php"              ascii nocase
        $ep   = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ ascii nocase
        $sp   = /system\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ ascii nocase
        $se   = /shell_exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ ascii nocase
        $b64  = /eval\s*\(\s*base64_decode/ ascii nocase
        $gz   = /gzinflate\s*\(.*base64_decode/ ascii nocase
        $preg = /preg_replace\s*\(.*\/e/ ascii nocase
        $ass  = /assert\s*\(\s*\$_(POST|GET|REQUEST)/ ascii nocase
    condition:
        $php and (1 of ($ep,$sp,$se,$b64,$gz,$preg,$ass))
}

rule Webshell_ASPX_Generic
{
    meta:
        description = "Generic ASPX webshell patterns"
        severity    = "CRITICAL"
        author      = "TEA Security"
    strings:
        $asp1 = "<%"                           ascii
        $ps1  = "Process.Start("               ascii nocase
        $ps2  = "ProcessStartInfo"             ascii nocase
        $ws1  = "WScript.Shell"                ascii nocase
        $ws2  = "CreateObject(\"WScript"       ascii nocase
        $cmd1 = "cmd.exe"                      ascii nocase
        $cmd2 = "cmd /c"                       ascii nocase
        $ado  = "ADODB.Stream"                 ascii nocase
        $rsp  = "Response.Write"               ascii nocase
    condition:
        $asp1 and (2 of ($ps1,$ps2,$ws1,$ws2,$cmd1,$cmd2,$ado)) and $rsp
}

rule Webshell_JSP_Generic
{
    meta:
        description = "Generic JSP webshell patterns"
        severity    = "CRITICAL"
        author      = "TEA Security"
    strings:
        $jsp1 = "<%"                               ascii
        $re1  = /Runtime\.getRuntime\(\)\.exec/    ascii nocase
        $pb1  = "ProcessBuilder"                   ascii nocase
        $req  = "request.getParameter"             ascii nocase
    condition:
        $jsp1 and (($re1 or $pb1) and $req)
}

rule Suspicious_Scheduled_Task_Payload
{
    meta:
        description = "Scheduled task XML with suspicious PowerShell payload"
        severity    = "HIGH"
        author      = "TEA Security"
    strings:
        $xml  = "<?xml"                ascii
        $task = "<Task "               ascii
        $ps   = "powershell"           ascii nocase
        $enc  = "-EncodedCommand"      ascii nocase
        $hid  = "Hidden"               ascii
        $sys  = "SYSTEM"               ascii
    condition:
        $xml and $task and $ps and (2 of ($enc,$hid,$sys))
}

rule AsyncRAT_Indicators
{
    meta:
        description = "AsyncRAT remote access trojan"
        severity    = "CRITICAL"
        author      = "TEA Security"
    strings:
        $s1 = "AsyncRAT"                ascii nocase
        $s2 = "Quasar"                  ascii nocase
        $s3 = "ServerCertificate"       ascii nocase
        $s4 = "Plugin.KeyLogger"        ascii nocase
        $s5 = "XmlDeserializer"         ascii nocase
        $s6 = "AES_256_Key"             ascii nocase
    condition:
        2 of them
}

rule Suspicious_LOLBin_Script
{
    meta:
        description = "LOLBAS-style execution in script file"
        severity    = "HIGH"
        author      = "TEA Security"
    strings:
        $r1  = "regsvr32"              ascii nocase
        $r2  = "rundll32"              ascii nocase
        $r3  = "mshta"                 ascii nocase
        $r4  = "certutil"              ascii nocase
        $r5  = "bitsadmin"             ascii nocase
        $r6  = "odbcconf"              ascii nocase
        $dl  = "DownloadString"        ascii nocase
        $dl2 = "DownloadFile"          ascii nocase
        $iex = "IEX"                   ascii
        $b64 = "FromBase64String"      ascii nocase
    condition:
        (1 of ($r1,$r2,$r3,$r4,$r5,$r6)) and (1 of ($dl,$dl2,$iex,$b64))
}

rule Ransomware_Behavior_Indicators
{
    meta:
        description = "Ransomware behavioral patterns in files"
        severity    = "CRITICAL"
        author      = "TEA Security"
    strings:
        $r1 = "vssadmin delete shadows"    ascii nocase
        $r2 = "bcdedit /set"               ascii nocase
        $r3 = "wbadmin delete catalog"     ascii nocase
        $r4 = "wmic shadowcopy delete"     ascii nocase
        $r5 = "DisableAntiSpyware"         ascii nocase
        $r6 = "YOUR FILES HAVE BEEN"       ascii nocase
        $r7 = "HOW TO DECRYPT"             ascii nocase
        $r8 = "bitcoin"                    ascii nocase
        $r9 = ".onion"                     ascii nocase
    condition:
        2 of ($r1,$r2,$r3,$r4,$r5) or
        2 of ($r6,$r7,$r8,$r9)
}

rule Credential_Harvesting
{
    meta:
        description = "Credential harvesting patterns"
        severity    = "HIGH"
        author      = "TEA Security"
    strings:
        $c1 = "sekurlsa"           ascii nocase
        $c2 = "lsass.exe"          ascii nocase
        $c3 = "SAM"                ascii
        $c4 = "SECURITY"           ascii
        $c5 = "procdump"           ascii nocase
        $c6 = "comsvcs.dll,MiniDump" ascii nocase
        $c7 = "password"           ascii nocase
        $c8 = "credential"         ascii nocase
        $c9 = "NtlmHash"           ascii nocase
    condition:
        ($c1 or ($c2 and ($c5 or $c6))) or
        ($c9 and 1 of ($c3,$c4))
}
