<#
.SYNOPSIS
  Script to check for IOC's left by  ProxyNotShell vulnerabilities CVE-2022-41040 and CVE-2022-41082.

  Reference:
  ==============
  Microsoft Security Response Center (MSRC): https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/

  Microsoft Security Blog: https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/

  Credits:
  ==============
  Author: RJ Sudlow (emberlake.ky)
  License: Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
  Dependencies: None
  Reference: HAFNIUM-IOC (https://github.com/soteria-security)

 
.DESCRIPTION
    Searches for IOCs related to ProxyNotShell identified by Microsoft and security researchers.
#>

<#
IOC's

Files:
================
DrSDKCaller.exe (C:\root\DrSDKCaller.exe)
all.exe (C:\Users\Public\all.exe)
dump.dll (C:\Users\Public\dump.dll)
ad.exe (C:\Users\Public\ad.exe)
gpg-error.exe (C:\PerfLogs\gpg-error.exe)
cm.exe (C:\PerfLogs\cm.exe)
msado32.tlb (C:\Program Files\Common Files\system\ado\msado32.tlb)

Hashes (dll.dll):
=================
074eb0e75bb2d8f59f1fd571a8c5b76f9c899834893da6f7591b68531f2b5d82
45c8233236a69a081ee390d4faa253177180b2bd45d8ed08369e07429ffbe0a9
9ceca98c2b24ee30d64184d9d2470f6f2509ed914dafb87604123057a14c57c0
29b75f0db3006440651c6342dc3c0672210cfb339141c75e12f6c84d990931c3
c8c907a67955bcdf07dd11d35f2a23498fb5ffe5c6b5d7f36870cf07da47bff2

Malicious IP's
=================
125.212.220.48
5.180.61.17
47.242.39.92
61.244.94.85
86.48.6.69
86.48.12.64
94.140.8.48
94.140.8.113
103.9.76.208
103.9.76.211
104.244.79.6
112.118.48.186
122.155.174.188
125.212.241.134
185.220.101.182
194.150.167.88
212.119.34.11
hxxp://206.188.196.77:8080/themes.aspx (URL)
137.184.67.33 (C2)


Updated URL Request Blocking Rule (IIS): “.*autodiscover\.json.*Powershell.*”
#>
param ($logPath=$args[0])
function IOCCheck-Powershell {
  [cmdletbinding()]
  Param (
    [Parameter (Mandatory = $True)][string]$logPath
  )
  $CVE202241040_PS = @()
  if (Test-Path "$logPath") {
    $totalLogs = Get-ChildItem -Recurse -Path "$logPath" -Filter "*.log" -ErrorAction SilentlyContinue
    foreach ($log in $totalLogs) {
      $CVE202241040_PS += Get-ChildItem -Recurse -Path $logPath -Filter '*.log' | Select-String -Pattern '.*autodiscover\.json.*Powershell.*'
    }
  }
  
  #Returning Results
  if ($CVE202241040_PS.Count -eq 0) {
    Write-Host -ForegroundColor Green "[+] No indicators found."
  }
  
  else {
    Write-Host -ForegroundColor Red "[!] IOC's found!"
    Write-Host -ForegroundColor Yellow "`n[*] IOC's found in the following locations:"
    $CVE202241040_PS | ForEach-Object { 
      Write-Host "[!] " -f Red -NoNewline; "$_" 
    }
  }
}

function IOCCheck-KnownIPs {
  [cmdletbinding()]
  Param (
    [Parameter (Mandatory = $True)][string]$logPath
  )
  $MaliciousIP =@(
    "125.212.220.48",
    "5.180.61.17",
    "47.242.39.92",
    "61.244.94.85",
    "86.48.6.69",
    "86.48.12.64",
    "94.140.8.48",
    "94.140.8.113",
    "103.9.76.208",
    "103.9.76.211",
    "104.244.79.6",
    "112.118.48.186",
    "122.155.174.188",
    "125.212.241.134",
    "185.220.101.182",
    "194.150.167.88",
    "212.119.34.11",
    "137.184.67.33",
    "206.188.196.77"
  )
  $CVE202241040_IP = @()
  if (Test-Path "$logPath") {
    $totalLogs = Get-ChildItem -Recurse -Path "$logPath" -Filter "*.log" -ErrorAction SilentlyContinue
    foreach ($log in $totalLogs) {
      foreach ($ip in $MaliciousIP) {
        $CVE202241040_IP += Get-ChildItem -Recurse -Path $logPath -Filter '*.log' | Select-String -Pattern $ip
      }
    }
  }
  
  #Returning Results
  if ($CVE202241040_IP.Count -eq 0) {
    Write-Host -ForegroundColor Green "[+] No indicators found."
  }
  
  else {
    Write-Host -ForegroundColor Red "[!] IOC's found!"
    Write-Host -ForegroundColor Yellow "`n[*] Malicious IP communications found in the following locations:"
    $CVE202241040_IP | ForEach-Object { 
      Write-Host "[!] " -f Red -NoNewline; "$_"  
    }
  }
}

function IOC-PostExploit {
  [cmdletbinding()]
  $MaliciousFiles =@(
    "DrSDKCaller.exe",
    "all.exe",
    "dump.dll",
    "ad.exe",
    "gpg-error.exe",
    "cm.exe",
    "msado32.tlb"
  )

  $KnownPaths =@(
    "C:\root\",
    "C:\Users\Public\",
    "C:\PerfLogs\",
    "C:\Program Files\Common Files\system\ado\"
    #"$env:ExchangeInstallPath\V15\Logging\HttpProxy"
  )

  $CVE202241040_Post = @()
  foreach ($path in $KnownPaths) {
    foreach ($f in $MaliciousFiles) {
      $CVE202241040_Post += Get-ChildItem -Path $path $f
    }
  }

  #Returning Results
  if ($CVE202241040_Post.Count -eq 0) {
    Write-Host -ForegroundColor Green "[+] No indicators found."
  }
  
  else {
    Write-Host -ForegroundColor Red "[!] IOC's found!"
    Write-Host -ForegroundColor Yellow "`n[*] Malicious Post-Exploit IOC's found in the following locations:"
    $CVE202241040_Post | ForEach-Object { 
      Write-Host "[!] " -f Red -NoNewline; "$_"  
    }
  }
}


Write-Host -ForegroundColor Magenta "ProxyNotShell (CVE-2022-41040 & CVE-2022-41082) IOC Checker."
Write-Host -ForegroundColor Yellow "[*] Please note: this may take a while to run."
Write-Host -ForegroundColor Yellow "[*] Starting check for Powershell IOC's..."
IOCCheck-Powershell $logPath
Write-Host -ForegroundColor Yellow "`n[*] Starting check for malicous IP communications..."
IOCCheck-KnownIPs $logPath
Write-Host -ForegroundColor Yellow "`n[*] Starting check for post-exploit IOC's..."
IOC-PostExploit $logPath