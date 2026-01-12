/*
 * Suspicious patterns in executables
 * These rules detect potentially malicious behavior patterns
 */

rule Suspicious_Base64_Execution {
    meta:
        description = "Detects Base64 encoded command execution"
        severity = "medium"
        category = "suspicious"
    strings:
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-enc " ascii nocase
        $enc3 = "-ec " ascii nocase
        $b64 = "FromBase64String" ascii nocase
    condition:
        any of them
}

rule Suspicious_Shell_Commands {
    meta:
        description = "Detects suspicious shell command patterns"
        severity = "low"
        category = "suspicious"
    strings:
        $sh1 = "/bin/sh -c" ascii
        $sh2 = "/bin/bash -c" ascii
        $sh3 = "cmd.exe /c" ascii nocase
        $sh4 = "cmd /c" ascii nocase
        $eval = "eval(" ascii
    condition:
        any of them
}

rule Suspicious_Network_Indicators {
    meta:
        description = "Detects suspicious network-related strings"
        severity = "low"
        category = "suspicious"
    strings:
        $sock1 = "SOCK_STREAM" ascii
        $sock2 = "socket(" ascii
        $rev1 = "reverse shell" ascii nocase
        $rev2 = "reverse_tcp" ascii nocase
        $bind = "bind shell" ascii nocase
    condition:
        ($sock1 or $sock2) and ($rev1 or $rev2 or $bind)
}

rule Suspicious_Persistence_Registry {
    meta:
        description = "Detects Windows registry persistence locations"
        severity = "medium"
        category = "suspicious"
    strings:
        $reg1 = "CurrentVersion\\Run" ascii nocase
        $reg2 = "CurrentVersion\\RunOnce" ascii nocase
        $reg3 = "CurrentVersion\\Policies\\Explorer\\Run" ascii nocase
        $reg4 = "CurrentVersion\\Windows\\Load" ascii nocase
    condition:
        any of them
}

rule Suspicious_Process_Injection {
    meta:
        description = "Detects process injection indicators"
        severity = "high"
        category = "suspicious"
    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtCreateThreadEx" ascii
        $api5 = "QueueUserAPC" ascii
        $api6 = "SetThreadContext" ascii
    condition:
        2 of them
}

rule Suspicious_Credential_Access {
    meta:
        description = "Detects credential access patterns"
        severity = "high"
        category = "suspicious"
    strings:
        $cred1 = "mimikatz" ascii nocase
        $cred2 = "sekurlsa" ascii nocase
        $cred3 = "lsadump" ascii nocase
        $cred4 = "SAM database" ascii nocase
        $cred5 = "credential manager" ascii nocase
    condition:
        any of them
}

rule Suspicious_AntiDebug {
    meta:
        description = "Detects anti-debugging techniques"
        severity = "medium"
        category = "suspicious"
    strings:
        $dbg1 = "IsDebuggerPresent" ascii
        $dbg2 = "CheckRemoteDebuggerPresent" ascii
        $dbg3 = "NtQueryInformationProcess" ascii
        $dbg4 = "OutputDebugString" ascii
    condition:
        2 of them
}

