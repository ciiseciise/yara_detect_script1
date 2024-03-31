rule Detect_Suspicious_Script {
    meta: 
        author = "Yara DetecWiz"
        description = "Detects recon activity in a script"

    strings:
    $a = "whoami"
    $b = "Get-LocalUser"
    $c = "C:\\Users"
    $d = "net"

    $e = "ipconfig"
    $f = "netstat"

    $g = "Start-Slepp"

    condition:
        any of them
}

