<#
================
Busy Bee Console
================

Version 3.0
© David Wang, Nov 2021

CAUTION:
1. Please start Powershell with your domain admin account
2. If you get this error message: bbc.ps1 cannot be loaded. The file bbc.ps1 is not digitally signed. You cannot run this script on the current system.
   Please run the following commands:
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -force
   Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Bypass -force (Elevated)
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -force
3. PSParallel module required for fast ping test:
   Install-Module -Name PSParallel -Scope AllUsers -Force (elevated)

   Max Error Code 157
#>
# The MIT License (MIT)
#
# Copyright (c) 2021, David Wang
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and A
# associated documentation files (the "Software"), to deal in the Software without restriction, 
# including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial
# portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#requires -version 5.1
#Requires -RunAsAdministrator

#Set-StrictMode -Version Latest
Set-StrictMode -Off

# Setup dependency for the 1st time
if (!(Get-Module -ListAvailable -Name PSParallel)) {
    Install-Module -Name PSParallel -Scope AllUsers -Force -Confirm:$false
}

Import-Module PSParallel 2>$null
Import-Module Invoke-CommandAs 2>$null
import-module ActiveDirectory 2>$null

# Preparing PSRemoting with IP address
Set-Item wsman:\localhost\Client\TrustedHosts -value * -Force

# Clear the global error variable
$error.clear()

# eMoji characters
$Global:emoji_angry    = [char]::ConvertFromUtf32(0x1F608) # 😈
$Global:emoji_sad      = [char]::ConvertFromUtf32(0x1F922) # 🤢
$Global:emoji_Laugh    = [char]::ConvertFromUtf32(0x1F601) # 😁
$Global:emoji_cry      = [char]::ConvertFromUtf32(0x1F629) # 😩
$Global:emoji_pout     = [char]::ConvertFromUtf32(0x1F621) # 😡
$Global:emoji_fear     = [char]::ConvertFromUtf32(0x1F626) # 😦
$Global:emoji_error    = [char]::ConvertFromUtf32(0x0274C) # ❌
$Global:emoji_check    = [char]::ConvertFromUtf32(0x02714) # ✔
$Global:emoji_tree     = [char]::ConvertFromUtf32(0x1F332) # 🌲
$Global:emoji_hand     = [char]::ConvertFromUtf32(0x0270B) # ✋
$Global:emoji_Flower   = [char]::ConvertFromUtf32(0x1F33B) # 🌻
$Global:emoji_Wait     = [char]::ConvertFromUtf32(0x0231B) # ⌛
$Global:emoji_Caution  = [char]::ConvertFromUtf32(0x026A1) # ⚡
$Global:emoji_Stop     = [char]::ConvertFromUtf32(0x026D4) # ⛔
$Global:emoji_gCheck   = [char]::ConvertFromUtf32(0x02705) # ✅
$Global:emoji_gError   = [char]::ConvertFromUtf32(0x0274E) # ❎
$Global:emoji_Question = [char]::ConvertFromUtf32(0x02753) # ❓
$Global:emoji_eMark    = [char]::ConvertFromUtf32(0x02757) # ❗
$Global:emoji_Star     = [char]::ConvertFromUtf32(0x02B50) # ⭐
$Global:emoji_UpArrow  = [char]::ConvertFromUtf32(0x021D1) # ⇑
$Global:emoji_Sun      = [char]::ConvertFromUtf32(0x1F31E) # 🌞
$Global:emoji_Money    = [char]::ConvertFromUtf32(0x1F911) # 🤑
$Global:emoji_Lenovo   = [char]::ConvertFromUtf32(0x1F31D) # 🌝
$Global:emoji_Windows  = [char]::ConvertFromUtf32(0x1F383) # 🎃
$Global:emoji_Key      = [char]::ConvertFromUtf32(0x1F511) # 🔑

# Global mutex for accessing shared resources from threads
$Global:createdNew = $False # Stores Boolean value if the current PowerShell Process gets a lock on the Mutex
# Create the Mutex Object usin the constructuor -> Mutex Constructor (Boolean, String, Boolean)
$Global:mutex = New-Object -TypeName System.Threading.Mutex($true, "Tom", [ref]$Global:createdNew)

Function Test-IPAddress {
    param (
        [string]$IP
    )

    if(($ip -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") -and ($IP -as [IPAddress] -as [Bool])) {
        return $true
    } else {
        return $false
    }
}

function ValidateSubnetMask ($strSubnetMask)
{
	$bValidMask = $true
	$arrSections = @()
	$arrSections +=$strSubnetMask.split(".")
	#firstly, make sure there are 4 sections in the subnet mask
	if ($arrSections.count -ne 4) {$bValidMask =$false}
	
	#secondly, make sure it only contains numbers and it's between 0-255
	if ($bValidMask)
	{
		foreach ($item in $arrSections)
		{
            if (!($item -match "^[\d\.]+$")) {$bValidMask = $false}
		}
	}
	
	if ($bValidMask)
	{
		foreach ($item in $arrSections)
		{
			$item = [int]$item
			if ($item -lt 0 -or $item -gt 255) {$bValidMask = $false}
		}
	}
	
	# Make sure it is actually a subnet mask when converted into binary format
	if ($bValidMask)
	{
		foreach ($item in $arrSections)
		{
			$binary = [Convert]::ToString($item,2)
			if ($binary.length -lt 8)
			{
				$binary = $binary.PadLeft(8,'0')
			}
			$strFullBinary = $strFullBinary+$binary
		}
		if ($strFullBinary.contains("01")) {$bValidMask = $false}
		if ($bValidMask)
		{
			$strFullBinary = $strFullBinary.replace("10", "1.0")
			if ((($strFullBinary.split(".")).count -ne 2)) {$bValidMask = $false}
		}
	}
	Return $bValidMask
}

function Get-IPrangeStartEnd{ 
    <# -----------------------------------------------------------------
        .EXAMPLE
            Get-IPrangeStartEnd -start 192.168.8.2 -end 192.168.8.20
            Get-IPrangeStartEnd -ip 192.168.8.2 -mask 255.255.255.0
            Get-IPrangeStartEnd -ip 192.168.8.3 -cidr 24
    -------------------------------------------------------------------#>

    param (
        [string]$start,
        [string]$end,
        [string]$ip,
        [string]$mask,
        [int]$cidr
    )

    function ConvertToINT64 () {
        param ($ip)

        $octets = $ip.split(".")
        return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3])
    }

    function ConvertToIP() {
        param ([int64]$int)

        return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
    }

    if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)}
    if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((ConvertToIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) }  
    if ($mask) {$maskaddr = [Net.IPAddress]::Parse($mask)}  
    if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)}  
    if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))}  

    if ($ip) {  
        $startaddr = ConvertToINT64 -ip $networkaddr.ipaddresstostring  
        $endaddr = ConvertToINT64 -ip $broadcastaddr.ipaddresstostring  
    } else {  
        $startaddr = ConvertToINT64 -ip $start  
        $endaddr = ConvertToINT64 -ip $end  
    }  

    $temp="" | Select-Object start,end 
    $temp.start=ConvertToIP -int $startaddr 
    $temp.end=ConvertToIP -int $endaddr 
    return $temp 
}

class controls {
    [bool]$check_scriptblock_completed               = $false
    [bool]$grant_scriptblock_completed               = $false
    [bool]$sList_scriptblock_completed               = $false
    [bool]$scan_scriptblock_completed                = $false
    [bool]$ListServices_scriptblock_completed        = $false
    [bool]$Firewall_scriptblock_completed            = $false
    [bool]$sccm_scriptblock_completed                = $false
    [bool]$DeleteProfile_Scriptblock_completed       = $false
    [bool]$TestPendingReboot_Scriptblock_completed   = $false
    [bool]$Who_scriptblock_completed                 = $false
    [bool]$EnablePSRemoting_scriptblock_completed    = $false
    [bool]$Service_scriptblock_completed             = $false
    [bool]$Hardware_scriptblock_completed            = $false
    [bool]$GetBitLockerKey_scriptblock_completed     = $false
    [bool]$SuspendBitlocker_scriptblock_completed    = $false
    [bool]$UAC_scriptblock_completed                 = $false
    [bool]$LocalAppList_scriptblock_completed        = $false
    [bool]$GetInstalledUpdates_scriptblock_completed = $false
    [bool]$Process_scriptblock_completed             = $false
    [bool]$Uninstall_scriptblock_completed           = $false
    [bool]$ISS_scriptblock_completed                 = $false
    [bool]$network_scriptblock_Connected             = $false
    [bool]$BSOD_scriptblock_Connected                = $false
    [bool]$QuerySession_scriptblock_Completed        = $false
    [bool]$user_detail_scriptblock_completed         = $false
    [bool]$WPK_scriptblock_completed                 = $false
    [bool]$InstallDCPP_scriptblock_Completed         = $false
    [bool]$DellSMBIOS_Get_Item_scriptblock_Completed = $false
    [bool]$DellSMBIOS_Set_Item_scriptblock_Completed = $false
    [bool]$DellSMBIOS_Catagory_List_Ready            = $false
    [bool]$HP_BIOS_List_Ready                        = $false
    [bool]$getBitLockerRecoveryKey_scriptblock_Completed = $false
    [bool]$System_Recovery_Configuration_Completed   = $false
    [bool]$HpBIOSList_scriptblock_Completed          = $false
    [bool]$HPCMSL_scriptblock_Completed              = $false
    [bool]$MonitorInfo_scriptblock_Completed         = $false
}

class eMojis {
    # eMoji characters
    $angry    = [char]::ConvertFromUtf32(0x1F608) # 😈
    $sad      = [char]::ConvertFromUtf32(0x1F922) # 🤢
    $Laugh    = [char]::ConvertFromUtf32(0x1F601) # 😁
    $cry      = [char]::ConvertFromUtf32(0x1F629) # 😩
    $pout     = [char]::ConvertFromUtf32(0x1F621) # 😡
    $fear     = [char]::ConvertFromUtf32(0x1F626) # 😦
    $error1   = [char]::ConvertFromUtf32(0x0274C) # ❌
    $check    = [char]::ConvertFromUtf32(0x02714) # ✔
    $tree     = [char]::ConvertFromUtf32(0x1F332) # 🌲
    $hand     = [char]::ConvertFromUtf32(0x0270B) # ✋
    $Flower   = [char]::ConvertFromUtf32(0x1F33B) # 🌻
    $Wait     = [char]::ConvertFromUtf32(0x0231B) # ⌛
    $Caution  = [char]::ConvertFromUtf32(0x026A1) # ⚡
    $Stop     = [char]::ConvertFromUtf32(0x026D4) # ⛔
    $gCheck   = [char]::ConvertFromUtf32(0x02705) # ✅
    $gError   = [char]::ConvertFromUtf32(0x0274E) # ❎
    $Question = [char]::ConvertFromUtf32(0x02753) # ❓
    $eMark    = [char]::ConvertFromUtf32(0x02757) # ❗
    $Star     = [char]::ConvertFromUtf32(0x02B50) # ⭐
    $Send     = [char]::ConvertFromUtf32(0x1F4E8) # 📨
    $Smile    = [char]::ConvertFromUtf32(0x1F600) # 😀
}

# Create a synchronized hash table
$syncHash = [hashtable]::Synchronized(@{})

[string]$syncHash.LOG_PATH = "C:\Windows\Temp\BBC\BBC.log"

# Loading WPF assemblies 
try{
    Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,system.windows.forms,System.Drawing
} catch {
    $e = "[Error 0000]"
    Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
    Throw "Failed to load WPF assemblies, script terminated."
}

# Loading xaml file
try{
    [xml]$Global:xaml = [System.Xml.XmlDocument](Get-Content -Path bbc.xaml)
} catch {
    $e = "[Error 0001]"
    Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
    Throw "Failed to load bbc.xaml, program terminated."
}

# Setup log file
if(!(Test-Path C:\Windows\Temp\BBC)) {
    New-Item -Path C:\Windows\Temp -ItemType Directory -Name BBC 2>&1 | Out-Null
}
if(!(Test-Path $syncHash.LOG_PATH)) {
    New-Item -Path C:\Windows\Temp\BBC -ItemType File -Name BBC.log 2>&1 | Out-Null
    [string]$tdt = [string](Get-Date -Format "dddd MM/dd/yyyy HH:mm K")
    Add-Content -Path $syncHash.LOG_PATH -Value "[$tdt] Log file created by $env:USERNAME." 2>&1 | Out-Null
    $item = get-item -literalpath $syncHash.LOG_PATH 
    $acl = $item.GetAccessControl()
    $permission = "Everyone","FullControl","Allow"
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.SetAccessRule($rule)  2>&1 3>&1 6>&1 | Out-Null
    $item.SetAccessControl($acl)  2>&1 3>&1 6>&1 | Out-Null
}

$syncHash.Get_WindowsProductKey = {
    # test whether this is Windows 7 or older
    function Test-Win7
    {
        $OSVersion = [System.Environment]::OSVersion.Version
        ($OSVersion.Major -eq 6 -and $OSVersion.Minor -lt 2) -or
        $OSVersion.Major -le 6
    }

    # Decoder implementation
    $edoc = "dXNpbmcgU3lzdGVtOw0KdXNpbmcgU3lzdGVtLkNvbGxlY3Rpb25zOw0KcHVibGljIHN0YXRpYyBjbGFzcyBEZWNvZGVyew0KcHVibGljIHN0YXRpYyBzdHJpbmcgRGVjb2RlUHJvZHVjdEtleVdpbjcoYnl0ZVtdIGRpZ2l0YWxQcm9kdWN0SWQpew0KY29uc3QgaW50IGtleVN0YXJ0SW5kZXggPSA1MjsNCmNvbnN0IGludCBrZXlFbmRJbmRleCA9IGtleVN0YXJ0SW5kZXggKyAxNTsNCnZhciBkaWdpdHMgPSBuZXdbXXsnQicsICdDJywgJ0QnLCAnRicsICdHJywgJ0gnLCAnSicsICdLJywgJ00nLCAnUCcsICdRJywgJ1InLCAnVCcsICdWJywgJ1cnLCAnWCcsICdZJywgJzInLCAnMycsICc0JywgJzYnLCAnNycsICc4JywgJzknLH07DQpjb25zdCBpbnQgZGVjb2RlTGVuZ3RoID0gMjk7DQpjb25zdCBpbnQgZGVjb2RlU3RyaW5nTGVuZ3RoID0gMTU7DQp2YXIgZGVjb2RlZENoYXJzID0gbmV3IGNoYXJbZGVjb2RlTGVuZ3RoXTsNCnZhciBoZXhQaWQgPSBuZXcgQXJyYXlMaXN0KCk7DQpmb3IgKHZhciBpID0ga2V5U3RhcnRJbmRleDsgaSA8PSBrZXlFbmRJbmRleDsgaSsrKXtoZXhQaWQuQWRkKGRpZ2l0YWxQcm9kdWN0SWRbaV0pO30NCmZvciAodmFyIGkgPSBkZWNvZGVMZW5ndGggLSAxOyBpID49IDA7IGktLSl7DQovLyBFdmVyeSBzaXh0aCBjaGFyIGlzIGEgc2VwYXJhdG9yLg0KaWYgKChpICsgMSkgJSA2ID09IDApe2RlY29kZWRDaGFyc1tpXSA9ICctJzt9DQplbHNley8vIERvIHRoZSBhY3R1YWwgZGVjb2RpbmcuDQp2YXIgZGlnaXRNYXBJbmRleCA9IDA7DQpmb3IgKHZhciBqID0gZGVjb2RlU3RyaW5nTGVuZ3RoIC0gMTsgaiA+PSAwOyBqLS0pew0KdmFyIGJ5dGVWYWx1ZSA9IChkaWdpdE1hcEluZGV4IDw8IDgpIHwgKGJ5dGUpaGV4UGlkW2pdOw0KaGV4UGlkW2pdID0gKGJ5dGUpKGJ5dGVWYWx1ZSAvIDI0KTsNCmRpZ2l0TWFwSW5kZXggPSBieXRlVmFsdWUgJSAyNDsNCmRlY29kZWRDaGFyc1tpXSA9IGRpZ2l0c1tkaWdpdE1hcEluZGV4XTt9fX0NCnJldHVybiBuZXcgc3RyaW5nKGRlY29kZWRDaGFycyk7fQ0KcHVibGljIHN0YXRpYyBzdHJpbmcgRGVjb2RlUHJvZHVjdEtleShieXRlW10gZGlnaXRhbFByb2R1Y3RJZCl7DQp2YXIga2V5ID0gU3RyaW5nLkVtcHR5Ow0KY29uc3QgaW50IGtleU9mZnNldCA9IDUyOw0KdmFyIGlzV2luOCA9IChieXRlKSgoZGlnaXRhbFByb2R1Y3RJZFs2Nl0gLyA2KSAmIDEpOw0KZGlnaXRhbFByb2R1Y3RJZFs2Nl0gPSAoYnl0ZSkoKGRpZ2l0YWxQcm9kdWN0SWRbNjZdICYgMHhmNykgfCAoaXNXaW44ICYgMikgKiA0KTsNCmNvbnN0IHN0cmluZyBkaWdpdHMgPSAiQkNERkdISktNUFFSVFZXWFkyMzQ2Nzg5IjsNCnZhciBsYXN0ID0gMDsNCmZvciAodmFyIGkgPSAyNDsgaSA+PSAwOyBpLS0pIHsNCnZhciBjdXJyZW50ID0gMDsNCmZvciAodmFyIGogPSAxNDsgaiA+PSAwOyBqLS0pew0KY3VycmVudCA9IGN1cnJlbnQqMjU2Ow0KY3VycmVudCA9IGRpZ2l0YWxQcm9kdWN0SWRbaiArIGtleU9mZnNldF0gKyBjdXJyZW50Ow0KZGlnaXRhbFByb2R1Y3RJZFtqICsga2V5T2Zmc2V0XSA9IChieXRlKShjdXJyZW50LzI0KTsNCmN1cnJlbnQgPSBjdXJyZW50JTI0Ow0KbGFzdCA9IGN1cnJlbnQ7fQ0Ka2V5ID0gZGlnaXRzW2N1cnJlbnRdICsga2V5O30NCnZhciBrZXlwYXJ0MSA9IGtleS5TdWJzdHJpbmcoMSwgbGFzdCk7DQp2YXIga2V5cGFydDIgPSBrZXkuU3Vic3RyaW5nKGxhc3QgKyAxLCBrZXkuTGVuZ3RoIC0gKGxhc3QgKyAxKSk7DQprZXkgPSBrZXlwYXJ0MSArICJOIiArIGtleXBhcnQyOw0KZm9yICh2YXIgaSA9IDU7IGkgPCBrZXkuTGVuZ3RoOyBpICs9IDYpew0Ka2V5ID0ga2V5Lkluc2VydChpLCAiLSIpO30NCnJldHVybiBrZXk7fX0="
    $code = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($edoc))
    # compile C#
    Add-Type -TypeDefinition $code

    # get raw product key
    $digitalId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DigitalProductId).DigitalProductId

    $isWin7 = Test-Win7
    if ($isWin7)
    {
        # use static C# method
        [Decoder]::DecodeProductKeyWin7($digitalId)
    }
    else
    {
        # use static C# method:
        [Decoder]::DecodeProductKey($digitalId)
    }
}

$syncHash.Log_scriptblock = {
    param(
        [string]$e
    )

    if(!(Test-Path C:\Windows\Temp\BBC)) {
        New-Item -Path C:\Windows\Temp -ItemType Directory -Name BBC 2>&1 | Out-Null
    }

    # Setup log file
    if(!(Test-Path C:\Windows\Temp\BBC)) {
        New-Item -Path C:\Windows\Temp -ItemType Directory -Name BBC 2>&1 | Out-Null
    }
    if(!(Test-Path $syncHash.LOG_PATH)) {
        New-Item -Path C:\Windows\Temp\BBC -ItemType File -Name BBC.log 2>&1 | Out-Null
        [string]$tdt = [string](Get-Date -Format "dddd MM/dd/yyyy HH:mm K")
        Add-Content -Path $syncHash.LOG_PATH -Value "[$tdt] Log file created by $env:USERNAME." 2>&1 | Out-Null
        $item = get-item -literalpath $syncHash.LOG_PATH 
        $acl = $item.GetAccessControl()
        $permission = "Everyone","FullControl","Allow"
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($rule)  2>&1 3>&1 6>&1 | Out-Null
        $item.SetAccessControl($acl)  2>&1 3>&1 6>&1 | Out-Null
    }

    [string]$tdt = [string](Get-Date -Format "dddd MM/dd/yyyy HH:mm K")
    Add-Content -Path $syncHash.LOG_PATH -Value "[$tdt] $e" 2>&1 | Out-Null
}

$syncHash.outputFromThread_scriptblock = {
    param (
        [string]$f,
        [string]$s,
        [string]$c,
        [string]$m,
        [bool]$n
    )
    $objHash = @{
        font    = $f
        size    = $s
        color   = $c
        msg     = $m
        newline = $n
    }
    $syncHash.Q.Enqueue($objHash)
}

$syncHash.Devider_scriptblock = {
    for($i=0;$i -lt 88;$i++) {
        if($i%2 -eq 0) {
            Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text "=" -NewLine $false
        }
        if($i%2 -eq 1) {
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "=" -NewLine $false
        }
    }
    Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text "=" -NewLine $true
}

[string]$syncHash.ping_color       = ""
[string]$syncHash.ping_text        = ""
[string]$syncHash.rdp_color        = ""
[string]$syncHash.rdp_text         = ""
[string]$syncHash.permission_color = ""
[string]$syncHash.permission_text  = ""
[string]$syncHash.uptime_text      = ""
$syncHash.Q                        = New-Object System.Collections.Concurrent.ConcurrentQueue[psobject]
$syncHash.emoji_error              = [char]::ConvertFromUtf32(0x0274C) # ❌
$syncHash.emoji_check              = [char]::ConvertFromUtf32(0x02714) # ✔
$syncHash.control                  = [controls]::new()
$syncHash.emoji                    = [eMojis]::new()
[int]$syncHash.count               = 0 # It is thread-safe
[System.Collections.Arraylist]$syncHash.CatagoryList  = [System.Collections.Arraylist]@("")
[System.Collections.Arraylist]$syncHash.AttributeList = [System.Collections.Arraylist]@("")
[System.Collections.Arraylist]$syncHash.HPBIOSList    = [System.Collections.Arraylist]@("")

$Global:reader = (New-Object System.Xml.XmlNodeReader $Global:xaml)
$syncHash.window = [Windows.Markup.XamlReader]::Load($reader)

[PSCredential]$syncHash.PSRemote_credential = $null  # The IT credential for PSRemoting

# AutoFind all controls
$syncHash.Gui = @{}
$xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'x:Name')]]") | ForEach-Object {
    if(!($_ -match "ColorAnimation" -or $_ -match "ThicknessAnimation")) {
        $syncHash.Gui.Add($_.Name, $syncHash.Window.FindName($_.Name)) 2>&1 3>&1 4>&1 | Out-Null
    }
}

$syncHash.Gui.rb_Target.IsChecked  = $true
$syncHash.Gui.rb_File.IsChecked    = $false
$syncHash.Gui.rb_NS_Mask.IsChecked = $true
$syncHash.Gui.rb_NS_CIDR.IsChecked = $false
$syncHash.Gui.rb_keyID.IsChecked   = $true
$syncHash.Gui.btn_Who.Content      = "$Global:emoji_Flower"
$syncHash.Gui.btn_Check.Content    = "$Global:emoji_check"
$syncHash.Gui.btn_AdmPwd.Content   = "$Global:emoji_Key"
Add-Type -Assembly System.Drawing

# Button images
$LED_Green  = "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"
$LED_Red    = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAJQUlEQVRYR5WX62tb9xnHv+eic3Ssu3WNLDuK7Th2HJdSU5I6TbZAST3avQl7sf8ge9EyNtheFPaibKRkY2MwxpKydi9W9maQjcFmZ7SQxIGuXuJcbMuy44tiWbJsWTcf3XWOznh+kpV0uCU98PA7yJaez3N/fhy+wWM2m8/JsvyeJEmvS5JkEQWB43kehmEYuq6XdE27a+j6le10euZFf5Z7gX9ULBbLDavVOmmz2WC1WmFXFFhlGbLJBJHjAMNAo9FAtVZDsVJBoVSCWipNazx/aWtrq/J1Or4WQJblaw6H43J3dzdIfC4XvDYbnF1d8JjNcJhMEDgOFV1HsdFAmQDKZeRUFXv5PHZyOWSLxevr8fgPvgriqwDMiqKk/X6/1efz4UgggLDbje95vRiu1aDnctArFRiaBo7nwUsSRKsVYnc3NmUZt/N57Obz2M5ksJVOI763V9yv132HeeMwALfFYkkHg0EuGAziaCiEH/f0wJdMoppIoJ7Po1mtMuXguBaAyQTebIZosUByuaAcOQI1EMDf0mkGENvexvr2tlEplbzRRCLzvDf+H4AsL4dCIa6vrw9nBgfxLsehuLSEajIJTVUBXQcnisxqOjlBYBDs4TgIsgzRbofZ74dtcBBThoHHySRWt7awnEgY+VqtKxaLVQ8gvgQgiqIaCoWsR48exXdHR/H9QgH7CwuoJZNo1uvsx3lZhmA2s5MzmVrSBjB0HUajATpFRYHs9cJ2/Dj+Y7Ph7tOniG5uYikeL0bW1myHAVzz+/2XSfm3R0fxbqOBwv37zO1ESUqZdHWBVxTwdBKQJAGCwCqBAdTrLETNSgW8KDIIx8gI/i3LmI3FML+xgSfJ5PX1zU2WmAceUMj14XAYJ4aG8IeeHmRmZlDe2ABvGB3FFGOBxGYDb7F0ICgU9JD1THmpBJ2kWAQvCCwnXK+8gj/m81jY2MDDtTWkCoUuSsoDgKlAIDA5MDCA37z2Ghyzs1AfPYJRq7Vi2tXFEowUU3wFhwMCnXY78wZHXjAMNGs1NMtl6Pv70AuF1qmqEKhvDAyg8dJL+DAaxYPVVSxubk7Hnj79DgMQRdHo7+/H2MgIfmuzIX3nDurb2xCo0SgKs9pkszHFotPJyo1EcLnAkzdkmbohjEqlpTSXg5bNtoSqplKB2edD9/g4/qxpuLe6ivsrK5iPRqmN4Zzdbr8zODiI98+dw/EHD5C/fx9cowGB6puspxq32yG6XBDdbpg8Hog+H0SvF4LbzcKBZhNNVYW2twctnYa2u8veG20I8qR9eBh7p07ho/l5/Hd5GWuJxHkCmPL5fJNDQ0P46/g4dm/eROnJEwiiCJEyvquLWS+S9d3dLeV+P0xHjsAUDEIMBiF0dzMApjiRQCOZRCOVYhANAspmWX5YwmG4z5/H1bU1zC4vY3F9fZoA1N7eXuvI8DA+CgSw89lnqKdSEKnNUvwtFogE4HTCRK73emEKBGDq6YGptxdSOAxTOMzypR6LoUGytfUMog2gFYssGT1nz+L3xSIDeLiyUuQ4jmuGw2Hu9NgYPhAE7N6+DT2fb8X/AIBC0I69qQ1AlkuhEMS+PgZEnbGRSECLx1Hf2oJGXtjZeRaG/X3IHg/cZ87gL5KEO0tLmItGDRqnBpXfxfFx/KRcRnpmBs1ikYWgUwFWK0ztELAcoPiTFwIBCD4feLu9lQO5XEspuX9nBw0KSSYDjT4nABpqp0/jH04nbi4sYG5pCeSBDsBPq1VWAax0DnJAUVphoCSkMFAiejws+QhGcDpZKVIVsPqnQUVKKQHbysmjjWIRstsN98QE/u5wYHp+Ho+iUQbQ7O3tZSH4pdmM3Vu3WOYKgtDKAxoy7UqguicIUspOhwO81drpA5QHBM96QD7PLKd3bX8fWrkMJRiE9/x5fMzzuBWJYGFpyWBJGAgErMMnTuCT/n7sfPopyvE4BJ5v5YEksUZCvYDKUSChJkR9gbqholAjaXVCasOVCgshgZBi6oYkTaqC/n74L17ElXQas0tLWF5eLrIydDqdk9QH/nnhAnamprAfiYCjFiwIDOL5OcBacbsNExh1QZqIBhFoWqsbUkMqlVhIyHK9XGYzw3HqFHxvv40fzc3h4eIi1ttleE6SpDvUhj+4eBEnFxeR+eILNnqZFygZ2yVJM5/B0DAym8HRMDKZgOenIXmBIKpV6CTkkVoNst/P4h8fG8OvPv8ckUgEiXYjokQwaPkYPXECfxoYYHlQXF3teIGmGoMgaykk7SnIRjHtBARArbjZZOVI7mYQbRj6jm1kBP4338T7qRQeRiJYWVnB5uYma8X0TNHSeezYMXz41lvwPHiA7L17qGcyBMc8QRAMhBRKEns/WEhoEWEPAeg6mprWmoy0GxgGlL4+Vv/qq6/iZ7duIRqNkvLpbDbbGkYAFI7jyuSF/mPHcGNiAunbt1GIRFgoDiDY+kUgtAUJAjvJ/fR3loQHOwHtBSTNJiS/H86XX4Z/chI/nJtDdHkZGxsbBNAFoDOO6fvXZFm+TKvYt8bG8PNAAFkayysrrImQCroDMIj2yRTTe9sKlojkBRKOY3G3j47Ce+ECfre7i5mFBaY8kUhcV1X1SwvJwYak2u12aygUwqXxcbzjdCI3N4fi2hpq6TSzipSS8KS8/d5ZMskDtD0pCszBIGwnT8IzMYFPCgX869EjxGIxUl7MZrOHrmT0O2YAZZfLxTbiieFhXB0dRf7xY5TW11FJpZg3KLm4ZrMF0F5GKSSkWHK7oYRCbPS6xsdxNRrF7MoK4vE4ksmkkclkyPWHL6VtS9wA0g6Hg/P7/exO8Os33sDR/X2UYjFUUynUqdO17wUEQQuJyWplyrt6emAdGkLCbscvZmaQ3N5GKpXCzs6OkcvlvAC+di0/8CZ5Iq0oitXj8bBbUY/fj3dOn8ZZh6O16agqy3LKAWY5zQmvF7Oqio/n5pDa28Pe3h4ymQydxXK5TMo7lh+6lndi+ezlGsdxl+12OxwOB+g8uB/67Xa4aQ5wHArVKjLlMiqVCkp0L1RVJvl8ns7ruq5/46vZ8ywKgBscx02azWZYLBYoZDGta9QLOI6Vn6ZpqNfrqFarDKJSqUwbhnGJSu0Qwzofvcjt+PnvnwPwHoDXeZ638DzfqcBms1kyDOOuYRhXALzw9fx/L3J+oJNiU+EAAAAASUVORK5CYII="
$bee_icon   = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAEi0lEQVRYhe2Ub2xTVRjG3/2hrDdbb9nttgLtuq5b721vK8E/YBiSoiYiCcQMasRoogkmwsQZE4KjklSjLogmwMSEMANsUQK6gPDBGetw0HVs0k3cWOdkYmBmi0s63O5V8d7exw8bsMyBV5QvZk/y5uSc9+T9Pec9J4doRjOa0Z2VKTMzs4yIrP9pVZZlXYIgrMvOzs6/yRYmFAr9LEkSZFmGLMuoqan5/baNvLvW8tKkqXFK4c4p222JROJ6fnJ0dXWBiNJ1QTtesf1ERJRtMHj6wvaxa+tms9kxtXAwGMyYSM/u6emZFn4tDAaDVw8/b2IUp8nNmlo0EAhkEhHV1dWN3Are29sLIkrTY2DBxJg9XTKRSCiTCxMRrVy5cvOt4MlkEkajcYkeOBHRA+Fw+INYLDZSUlIiElHG5GRVVdWb1wpLkgQiSk8mkzeFd3Z2agaDQdBFbmhoWF9dXT2ACSWTSfx2xoPInkLYrbP2EBEFg8GMSQ8xtXPnznpZljE8PPwXeEVFRYR0tp1CoZA9lUphYGAA8XgcQ0NDAIBf4yKUdg+UUzwqH58zQkR07NixyOjoKCRJgiRJ6O7uhizLGBwchCzLqKuru5CTk8PpbTkREUUikW0Mw2BkZAQWiwWbNm0CAKjn/VDjXigtApRmHm7H7IYtlUWPbH/jMWzdGkJTUxP6+/sxNDSEA/t3YdGi+1t8Pp/rH8GJiGpra8u8Xi+OHDmCyspKlJeXoz1aj1SPH2qHCCU2buDMPge0ywsROyFi44YK7N27F4Pnn4Z2aQFOHPTinrvvw9KyZeiOlo2tX+cr0G3gmUBR1venN+Bi6xPojL6F9pOvIvXdXVC7fFDP3ujA6BduqBf86D/lgej1QfT6oPT5oPX70XpUgE/0wyf6cSEqInXpXmx72btQlwEAaUqbB+o3IlLn/Uj1+LHxKQ5qpwilzQPlNA+lmUfvoWJoCREXmwS4S3m4S3n80e2FlhDR9okbvFsA7xbQ96UArc8HqcsP3V24fLy090y9EyfeK8SH223jd9/uuX56pZnHi0/mQjvnQfzjEjidxXA6i5E654H2rQeN+1wodo7HwEkeWrcXV9oEuFyu5boMBAKBzLGIO6W0CFBahfF7nzi50szj0OvzED1QDC0uoPY1B2w2O2w2O7QOAVqHgF1VDththbDbCjEW46F1CPjxs1JkZWVdJqI1ukwEg5RxfIf966tf3QBf+bwUjy4xw8JZIEd5qG0CVj04F9YCK+bPs0JtF6C2C1i7Yi6s1vFQ2sbXGt8vQl5e3rS/6t+KZdk5ZjOZD9c6V3G5OVdZ1oRorQNqC4/8PA4cx2H54jyorTzUVh4OGweOs8DCWaDGeKgxHrs3Fxy9Lfg0Sns+yMmjETfkJjdYEwvWxOLTdwqhRnmoUR4sy4JlWZQ4zFBP82jcbf/oX1PD4XD62Ub3Lwd3zD8cCAQytzybv2RD0DLMGBkwRgZXm3kop3j80OACwzBgGAarl5nPrX4oX/8fcJtKMxqN88PPFTz89gv5a1YszllqMply7zR0RjP6f+lPeSFSHksovkAAAAAASUVORK5CYII="
$alert      = "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"
$StartApp   = "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"
$VBE_logo   = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAB2AAAAdgB+lymcgAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAA7cSURBVHic7Zp7XFVluse/67Lvm9tmgwJyByXBRFEw0zGp1Mqs1Dqertqx+5RW08WZ00yXcabpajblTDXW9PGWHT1jGl4SdQIzNUUxQQUBEQW5s1HYF/Za548l5A7QnATP5xx+nw+fD/tdz/u8z/O8631u74I+9KEPfehDH/rw/xXSz5grAkGA5ez/7ksiUS9DuAhaGzAVuB4YDsTia8AK4CCwC1gJfH+JZLzsGAj8HXABavufwWBQA/0DVbvNrgYFBKmiIKrnPgf2AXdycUbudZxPOCPwEvAUIMuyTNSAaCLDBhATGYPJaPIh9nq91DfWU3mqksKiQhqaGtof7QIeA77rAfl/NrozQDSwGhguyzJJCVcwMGEgtgAbsvTT3EblqUp27NlBdW01aP7hYeDjSyH0pURXBkgGNgHhwUHBpA/PwBZkw2q24PF4KC4t5kTVCWrqanC5XLg9bvQ6PcFBwdiD7QyMG4jdZgdAVVXyC/PZlbdL9Xq9ArAcKO899bpEC7AFyIXOBogCdgDhUQOiSR+WjtFgxKDXs3vfbgqLCvF4PAAIgkBQUBB6vYGammq8Xm8Hk5DgEK4eeTX9Q/sDUFldSVZ2lurxeP43+YOlwL3nCqQHtgMjIiOiyBiegUGv50zLGbbkbsHR7MBoNDLjzru56eYpjBo1Cj8/K7IkoqoqZWVlrFu7luVLl5Cfn48gCCQPSmb0iNGIokhVTRVZ2Vm43W5Sp04g5qrUjoUNOomQYGOvaN1YVUfWOyuor6gGeOJcA7wE/NYWFEzmmEwkSaL5tIONWzfi9Xq5bep05r/6OrbgYHSyhEEvIQidN1RVVZYvW8pv5s2jurqamMgYJoybgCiKFJUWkZ2TjV+/YGav/jMGixkAs1EmZoC1N/QHoPJIOc+n3YuqqkfFs2PRwHOiKDIydQSCIHD6dDObtm5CURReff1NFn24WFNeJ2E0yF0qD9rRuPOuu8nd8S2JiYmUHS8jOzcbgMTYROKi42g+Vcc3H6zsHW27QNjAKAL7BwPEthvgacAwKH4Q/n4BAOTuyqXN28b8V19n5v0PAKDXSQiqF0dT0wUXiYiIYFP2FuLi4zladpQjJUcAGJsxFkmSyPt8A86m05deu58ISScBiCJgAmYJgkB8bAIAR44epsnRxKQbbuT+2Q8C0NTUyGMPP0j/EDth/UJJHZJC9ubNPkznPf8cKVckkXJFEjdOmoifnx8fLV6MJEls370dt8eNyWgiISYBd0sr+Wt855+LtW8s4cVxD+FxXlyGXX6gmOeG3cPBbXvOSxeZEo8oy3kiMAmwhvcLx2Q0oSgKh4sPo9Pp+ONrbwLgcbu5/dbJLF+2FLPFQuLAgRQXF3PLzZN9jHC8vJzS0lJKS0v557ZtnDhxgoyMUdxz7324XK6OtyB5UDIARdt2ditg/le7KNlzCEdNQ7c0XeHorgIqi8o5urvwvHRzV8xn4YGV14vAeIDwsAgAqqqrcLqcTLpxMmHh2tiyJZ+Sn59P5rXXUnS0hH35B/h0yVIAnn5ybgfTJcuWc8bpYnxmps9ijzz6KACFRZpQofZQTEYTFfsO4TrdAsDBrXtYPX8xzXWdj5eqKOQu28h//+GTTs+aaxtZ8ZtFFH3bdelRnl/Msuffo6as0mdcEEWCwkIUGUgDCPQPBKC2rgaAW6dO6yDO26u9TnPmPonZrHnuqdOmMf/3r3CosJD6+jpstuAuBQBIGTKExMREiouLcbvd6PV6QoJDKD9RTl3JcYLsyWz7eC07V2/lq0WrufXXM/G2tQFw5NvvWb/wM8ryDiPrddw0dwZ68w8hszTvCFnvrGD9ws+46o7rCIkN7zDMx0+8wT///iWKVyE2LYmQmLCOeccPlvCX++eny0CsKIr4+/kDdOTwQ4YM7SB2e1wA+Af4+ygWGKAZzel0dat8O4anjaCoqIja+lrC+4djt9k1Axw7QUJ6MjMXPo1/SBBb/raGpc++2zFv0ayXAUjISOae1+f4KA9w5fXpPPjBr/n8dx/wzWdfdYxvfO9zAKw2f6b9djajpo33mbdo1stUFJSuEQGbJEmIohYQWp2tAERGRXUQC5egoBsQOUDj79L4y7IMgPuM9tsS6Mc9b87hhez3MVrNPnNvnXcfL2x+j9jhg7rkPebOifxp3xKuGJvqMx4zbBCv5y/j2tm3IIiizzOndvQMIiCjdmbaXZz/V9Fu4Pa12vkrbT+k0HlZ3/Dne3/XLlwH1r6xlKXPvkuL40yXvKuKj/P+zJcpzNnnM16Wd5g3bnuWo7sLupcLcCiq0jEgS9rONDZcnPe9EOrr6jX+Z3deUbQ1DX4WAFb85194+4551B6rYuSt1xCRFAPApF/egd5oYNOiVbww+j9oc3l8+JbsOcS8kTPZt/4b+idEctXt1wKQNmUskSnxHN1dwCvXPcbBrV2HRRE47vV6aWnVrB4UGATA/v0/WLN999xu35jscrt8lDof9u3LA+ioFOsbNIP499d+B4XbSRqTyq83vMPjS17CGqwlZBMfm85r+5ZwzazJ9IuLQJR9y3GDxUhkSjwz5j/CH3Z9TNIY7RjEDkvile0fMXPBU0RdmYjR6tu/aIeM1rq6sr6hHrPJjC3QRsmxErZt2cy4azTHERsXD8CX69YxZsxYAEpKSig4eJDAoCCCg7uPAACnTp0if/9+AvwDsJi1Ha9tqAVBICRe8zUTH53OxEendzk/oJ+N+999pstnEUkxvJzzQZfPREkkc/YtZM6+pVvZRGAbQM3Z8BcRFoEkSSxftgTnWYd476z7sdmCWbhgAXdMn8avnnqSzHG/wOVy8cwzzyJdoEny6Sef4PF4SDibaTafbsbR7CA4JgKLPajLOfaofpj8LFhtAefl3WletFaCnxvyzgcRWAt4yyuO0eZtQ683EBMZS2NDAwvffktjag9l2cqVREdH8+W6dSx6/33q6up4Yu5cHp8zpxPTmJhYrFYroSEhVFVVsWDB20iSxKA4zYsfKj6EqqokjkvvVrBZC3/FWwUrMFgurkwecl067x37osMXdAdFUQHUdle/BpiSNnQEcdFxeDxusrKzUBSFL7I2MTxtBKIoIOBle04OTU1NpI0YQWxsbJfM3W43ztZWLFYr/3b7dNZnZTFi2EhGDElDURSWrl7KmdYWHlrzPkFR4b1eDjdVNzAncSqKVznZ7r3+BEwpOFJAZHgkOp2ejGEZ5OzM4a4Z01m5ag1DrhyKXq/j+gkTLriAXq9HlmUeeuAB1mdl0S+0H6mDtcRq74G9nGk5g95sxHW6lcaKKlwGGbNHi/1Gqwn/kB+ORWvzGZprL1x9/lTUllfx+YsfongVgE/PDfYrgdujB0STPjwDWZI5VFxI3oE8/P39+f0fX+OOGXdi0Mvodec/8xUVFTzy0INsyc7GHmxn0jWTsFqs1DfWs2rdf+FVlG7nCoKgPrXq1S1DJ15Vf6bRIc9JmDbZ3erSXQrlf4QcYMK5BggH9gP2kcPSO1rfh4oK+W7/dyiKwlVXj2H2gw8zefJkLGYTP86VysrK+PCDv/K3jz6i2eEgrH8YmaMz8bP64XK7WLNhDfWN9byYNortVSf56kQ5gBfYeg6bOuCXQC1az/Id4IpLqHgjWtN3MeD9cbp3HbBeEAQ5I20UkeGRWMwWHI4mvt6Z01EoWa1WBienMHDQIPQ6HU1Njez57jvKysoA7QgMTR5K6uBUJEnC5XaRlZ3FqZpT3BQZyxcTp9DkdpH+jxVqsaNRAFLRjN/r6CrfnQEsFQRBTB6UQlJiElazBYPewPGTxzlSeoSTVZW0tPimpYIgEB4WTni/cAYnDu64OKmpq2FLbjYNTY2MDxvAFxOnYJF1rC0v4e6tGzntcaNCAnC0x7XtAt0l/Dej9fAtwTY7w1JSCQsNw2QyIQpaVuhodtB8uhmv4sVsMmO1WDEafghZHo+H/QX72XtgL4qicHNUHMszb8Asy7xxYC/P78pFUVX0krTJ7fVO7HFNu8H5Kp7BaDc56QD9Q8OIj4knPjoOs8nc7aS6hjqKS4spOFKAy+3CKEm8mj6Gx5NT8SheHs3dyuIjBzHKMl5BUM/eM9yFZvBex4VKPhmYCbyAdmmCKIoEBQQRGBCI1WxFFEVana20Oluprq3uKKdlQeSexCReGJZBjJ8/tc5Wpm/+kq+rTmAzWxg/fhJOl5Os7CxVVVU3MA7ovkfWQ/ipNa8M3AD8O9r1uL0bOo8Ax1RIiDVZ2HnDVOw2GwWN9dyy6QuOOpqIsocy7pqJHTXB94e+J3dXLkAV2tt2/GdpdJH4V4v+aDTHZQN0aKHlFFph5ZYFYVWbqt42zhbCk0OGc9+ObTS5XQyOjmf01eM7VY85O3M4ePggaFfqY4Fe65f31F2dWS8IO9yqeuW5g2MyxpAyMKXTqoqqkLU5i4rKCoB/ANOA7rOlS4if84nM+eDxwqpAWR8fbjKbW7zKh15VGX2y6qRgD7YT4O9b4QmCQHRkNGXlZThdziS0bxO6vzS4hOgpAwC0OBXvygaPe4FXVb4CWhVVub6isoIB4ZGdIoksyURFRFFUWqS2edvGACeBvT0oH9CzBvgxtgMRbW1taZXVlcRGxaLX6X0IDAYD/UL6CUWlRaqqqjeg5etlPSlUbxoAYIMgCL9odbbG1DfWExsViyT6iuBn9cNitghlx8sktIRsFXBpG5TnoLcNoADrBEGY4Wh2BLg9HiLDBnTqQNttdlxuF9W11WYgE1hCD32G19sGAO0TlU2CIMyqrq3WGQxGQu2hnYwQGR5JTV0NTc1NoYAfsL4nhBEvTNIjKFBVdTqg7Nz7LccqjnUiEASB8WdzBkEQZtJDm3W5DADajj7l9XrZtmMbNQ21nQhMRhP+Vn9UVbUCF9cd/Ym4nAYArdnxV6fTSfbX2Zw+45sAOpodNDoakUTJQQ85wsvhA36MjYIgjHU6W2Nq6muIjIhCr9NR11DHhi0bcLqcSJL0lqIo2Zdb0J6ETRTEYkCVZVkN9A9UBUFQAdVkNG1Gqzf+zyNUEqXPRFFsA1SD3nBap9PN4fIf016HDi3s9aEPfehDH/rQhz70KP4HXcNUvH/YZPEAAAAASUVORK5CYII="
$SUST_logo  = "iVBORw0KGgoAAAANSUhEUgAAACgAAAAoCAYAAACM/rhtAAABWklEQVRYhc3VPU4DMRAF4AdSJCg5RgoKCo5AwS24BB2FvVG0VFAjCg7BGejp0nEDOoIUJWEpUABvbO94POvxk1x5d+fT+GcBXyzeYNAVHu9eixODlQKsPzYhnDbMHYO40oka3InH4rhdLK73gf19px23WStUhdvFMWkAf+o91wmkHEY1oMWr97Q+YFIHkHrvqQDJl7IG0GAZAd7XAKR3rzgwFVcUaPEVxDW40QV2OGB1rxiQiysCjOEaXNUNTH2fcOTb3/kWJ6PjkoD/cX9LdMrCNTiXBT7hKFjs1oO8w7FI98hAg5dowRZnwY/m4MjAoaIGHea4HHyuw+F4QArSYCHavWQgDSmHYwF5yPSlzQKmInPCBlKRuckCDiElkg0MI9f1AH1IqYgBAWCGKea4EMNFgQZb0UI83Hq/aWMsEzdeS38vWXwWh1l8xPc093c21vBGG0XeZhXBvgG7P82B5QbtPgAAAABJRU5ErkJggg=="
$Store_Logo = "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"
$Event_Logo = "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"
$Ins_Logo   = "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"
$mon_Logo   = "iVBORw0KGgoAAAANSUhEUgAAAC0AAAAtCAYAAAA6GuKaAAACsElEQVRYhe2Yz0/TYBjH95/stNuysY2tv94CQdKiY8UbMItAEATiLssOYpt4acf+gXrT9F4ysyaG7gKHmpiIFyOHjWSe1BsnDZyWrxczpzhcJasb6Tf5XJ7kffPpk6dP0oZCQYIECRKk9bEFvVyGpmmoVCrY29tDpVKBpmvQdR26rg+mrmko62W0Wi14lh5PpjA9OYkplsEUS2Oa+QHL/IQZQJ1hMDnNI5VKeZPetywQnmA2K2Hl+SvIxj7yz6zBY1iQXxzgdnYePCGwLKt/cduugScEc/n72HnfxubrM39wz7D9oQ1paQUThEOtVutf+mW1Cp5wyC7K2D6+wIOjT/5w+Blb775BWpAxQThUq9X+pev1OgjH/iK9cfRl8HRJ84RDvV7vX9pxnKGQdhznhnf6TzPtt7TnmbZteyikbdu+4Z0eyZkOtodfnR7JmQ62h1+dHsmZDraHX50eyZm2bRvkkrT/HwH/uD2WsXN8gY1D/zr9sCNNvHXacQ7AcwS5/DK2Gm1sHJ9jc9C8Pcf6m6/YbrYxv7jm/UV0XRdsJg1BEHB3eR1SfhVz+VXkejDngV7ns0srePTkKXL5NQjCLVAUBdd1vf1GkGUZqWQSTCYNlsp0YDLpDiyVAUtnIAozyM6Kf0UUZsDSl++h02nksndwb3EB48kEkskUZFn2/rOmO81mE6enp2g2m/i9HgqFQqIogqIocBzXE4qiIIoius9139NoNHBycnI9US8xTROxWAw0TfckFovBNE3/pK6KaZqIRqOgaRoMw/SEpmlEo9H/I24YBkqlEiRJQjgcRiQSQTweRyKR6DA2Ntahux6PxxGJRBAOhyFJEkqlEgzDGPxDqKqKQqGAYrEIRVGgKApUVcXu7uMOqqpeWVcUBcViEYVCAYqiDMfIBAkSJMhw5juc0XuWGLhIegAAAABJRU5ErkJggg=="
$Cred_Logo  = "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"

$StartAppLogo = [System.Convert]::FromBase64String($StartApp)
$syncHash.Gui.Start_Logo.source = $StartAppLogo
$VBELogo = [System.Convert]::FromBase64String($VBE_logo)
$syncHash.Gui.vbe_icon.source = $VBELogo
$SUSTLogo = [System.Convert]::FromBase64String($SUST_logo)
$syncHash.Gui.SUST_icon.source = $SUSTLogo
$StoreLogo = [System.Convert]::FromBase64String($Store_logo)
$syncHash.Gui.store_icon.source = $StoreLogo
$EventLogo = [System.Convert]::FromBase64String($Event_logo)
$syncHash.Gui.event_icon.source = $EventLogo
$alertLogo = [System.Convert]::FromBase64String($alert)
$syncHash.Gui.alert_icon.source = $alertLogo
$syncHash.LED_Green = [System.Convert]::FromBase64String($LED_Green)
$syncHash.LED_Red   = [System.Convert]::FromBase64String($LED_Red)
$InsLogo = [System.Convert]::FromBase64String($Ins_logo)
$syncHash.Gui.installDPP_icon.source = $InsLogo
$syncHash.Gui.HpList_icon.source = $InsLogo
$mLogo = [System.Convert]::FromBase64String($mon_Logo)
$syncHash.Gui.Monitor_icon.source = $mLogo
$CredLogo = [System.Convert]::FromBase64String($Cred_Logo)
$syncHash.Gui.Credential_icon.source = $CredLogo

# create the runspace pool and pass the $syncHash variable through
$SessionVariable = New-Object 'Management.Automation.Runspaces.SessionStateVariableEntry' -ArgumentList 'syncHash', $syncHash, 'Synchronized hash table'

$SessionState = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$SessionState.Variables.Add($SessionVariable)
$MaxThreads = [int]$env:NUMBER_OF_PROCESSORS + 10
$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads, $SessionState, $Host)
$RunspacePool.ApartmentState = [Threading.ApartmentState]::STA
$RunspacePool.Open()

$syncHash.Gui.SB.Text = $env:USERDNSDOMAIN + "`\" + $env:USERNAME + " | " + $env:COMPUTERNAME + ' | ' + $env:NUMBER_OF_PROCESSORS + ' CPU Core(s)'

# create a "Jobs" array to track the created runspaces
$syncHash.Jobs = [System.Collections.ArrayList]@()

#Timer for updating the GUI
$syncHash.timer = new-object System.Windows.Threading.DispatcherTimer

# Setup timer and callback for updating GUI
$syncHash.Window.Add_SourceInitialized({            
    $syncHash.timer.Interval = [TimeSpan]"0:0:0.10"
    $syncHash.timer.Add_Tick( $syncHash.updateBlock )
    $syncHash.timer.Start()
})

#Timer for updating the terminal
$syncHash.timer_terminal = new-object System.Windows.Threading.DispatcherTimer

# Setup timer and callback for updating GUI
$syncHash.Window.Add_SourceInitialized({            
    $syncHash.timer_terminal.Interval = [TimeSpan]"0:0:0.10"
    $syncHash.timer_terminal.Add_Tick( $syncHash.updateTerminal )
    $syncHash.timer_terminal.Start()
})

#Timer for Ping
$syncHash.timer_ping = new-object System.Windows.Threading.DispatcherTimer(1) # lowest priority

# Setup timer and callback for Pingtest
$syncHash.Window.Add_SourceInitialized({            
    $syncHash.timer_ping.Interval = [TimeSpan]"0:0:10.00"
    $syncHash.timer_ping.Add_Tick( $syncHash.pingtest )
    $syncHash.timer_ping.Start()
})

function Show-Result {
    [CmdletBinding()]
    param(
        [string]$Font,
        [string]$Size,
        [string]$Color,
        [string]$Text,
        [bool]$NewLine
    )
    
        try{
        $RichTextRange = New-Object System.Windows.Documents.TextRange( $syncHash.Gui.rtb_Output.Document.ContentEnd, $syncHash.Gui.rtb_Output.Document.ContentEnd ) 
    } catch {
        $e = "[Error 0002]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }

    if($Text){
        $RichTextRange.Text = $Text
    } else {
        $RichTextRange.Text = "          "
        $e = "[Error 0003] Text Null value detected."
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
    }
    
    if($Color){
        try{
            $RichTextRange.ApplyPropertyValue( ( [System.Windows.Documents.TextElement]::ForegroundProperty ), $Color ) 2>&1 | Out-Null
        } catch {
            $e = "[Error 0004] : Color Null value detected."
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        }
    } else {
        $RichTextRange.ApplyPropertyValue( ( [System.Windows.Documents.TextElement]::ForegroundProperty ), "Red" )
    }
    
    if($Font){
        try{
            $RichTextRange.ApplyPropertyValue( ( [System.Windows.Documents.TextElement]::FontFamilyProperty ), $Font ) 2>&1 | Out-Null
        } catch {
            $e = "[Error 0005] : Font Null value detected."
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        }
        
    } else {
        $RichTextRange.ApplyPropertyValue( ( [System.Windows.Documents.TextElement]::FontFamilyProperty ), "Courier New" )
    }
    
    if($Size){
        try{
            $RichTextRange.ApplyPropertyValue( ( [System.Windows.Documents.TextElement]::FontSizeProperty ),   $Size ) 2>&1 | Out-Null
        } catch {
            $e = "[Error 0006] : Size Null value detected."
            &Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        }
        
    }else{
        $RichTextRange.ApplyPropertyValue( ( [System.Windows.Documents.TextElement]::FontSizeProperty ),   "18" )
    }
    
    if(!($NewLine -eq $null)){
        if($NewLine) { $syncHash.Gui.rtb_Output.AppendText("`r")}
    } 
    
    $syncHash.Gui.rtb_Output.ScrollToEnd()
}

function Splash {
    $copyright = [char]169

    $syncHash.Gui.rtb_Output.Document.Blocks.Clear() # Clear output window

    $Image64 = "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"
    $Image = [System.Convert]::FromBase64String($Image64)
    [System.Windows.Forms.Clipboard]::SetImage($Image)
    
    Show-Result -Font "Courier New" -Size "10" -Color "Yellow" -Text "     " -NewLine $true
    Show-Result -Font "Courier New" -Size "10" -Color "Yellow" -Text "     " -NewLine $true

    $syncHash.Gui.RTB_Output.ScrollToEnd()
    $syncHash.Gui.RTB_Output.Paste()
    
    $t = "Busy Bee Console"
    Show-Result -Font "Courier New" -Size "26" -Color "Chartreuse" -Text $t -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "Chartreuse" -Text "$copyright David Wang, Dec 2020" -NewLine $false
    Show-Result -Font "Courier New" -Size "20" -Color "Cyan" -Text "   Version 2.0" -NewLine $true
    Show-Result -Font "Castellar" -Size "20" -Color "Orange" -Text "  " -NewLine $true
    Show-Result -Font "Times New Roman" -Size "20" -Color "SteelBlue" -Text "Busy Bee Console, a great tool for IT guy's daily life." -NewLine $true
    Show-Result -Font "Times New Roman" -Size "20" -Color "SteelBlue" -Text "It is dedicated for IT field technicians to perform remote troubleshooting in an enterprise domain environment." -NewLine $true
    Show-Result -Font "Times New Roman" -Size "20" -Color "Lime" -Text "It's made for people who has zero knowledge of Powershell and still want to enjoy the power of powershell." -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "Chartreuse" -Text "  " -NewLine $true
    Show-Result -Font "Times New Roman" -Size "15" -Color "Yellow" -Text "BBC is a WPF application coded in Powershell and XAML. WinRM, network sharing and RPC need to be running on remote computers." -NewLine $true
    Show-Result -Font "Times New Roman" -Size "15" -Color "Yellow" -Text "You need a domain admin account to run this program." -NewLine $true
}

$syncHash.pingtest = {
    if([string]::IsNullOrEmpty($syncHash.Gui.cb_Target.text)){
        $syncHash.Gui.img_LED.source = $null
        return
    } 

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $syncHash.Gui.cb_Target.text)
    } catch {
    }

    if($test) {
        $syncHash.Gui.img_LED.source = $syncHash.LED_Green
    } else {
        $syncHash.Gui.img_LED.source = $syncHash.LED_Red
    }

    Remove-Variable -Name "test" 2>$null
}

$syncHash.updateTerminal = {
    $objHash = @{
        font    = ""
        size    = ""
        color   = ""
        msg     = ""
        newline = $false
    }
    if($syncHash.Q.Count -ne 0){
        [bool]$ok = $syncHash.Q.TryDequeue([ref]$objHash)

        if($ok){
            Show-Result -Font $objHash.font -Size $objHash.size -Color $objHash.color -Text $objHash.msg -NewLine $objHash.newline
            if($objHash.msg -match "completed"){ # When completed, save the result to a file located in c:\PSScanner
                if(!(Test-Path -Path "C:\PSScanner")) {
                    New-Item -Path "C:\PSScanner" -type directory -Force -ErrorAction Ignore -WarningAction Ignore -InformationAction Ignore | Out-Null
                }
                $range   = New-Object System.Windows.Documents.TextRange($syncHash.Gui.RTB_Output.Document.ContentStart, $syncHash.Gui.RTB_Output.Document.ContentEnd)
                $dt = Get-Date -Format "MM-dd-yyyy-HH-mm-ss"
                $path = "c:\PSScanner\" + '[' + $dt + ']' + '-output.txt'
                $fStream = [System.IO.FileStream]::New($path, [System.IO.FileMode]::Create)
                $range.Save($fStream, [System.Windows.DataFormats]::Text)
                $fStream.Close()
            }
        }
    }
    Remove-Variable -Name "objHash" 2>$null
    Remove-Variable -Name "ok" 2>$null
}

$syncHash.updateBlock = {
    if($syncHash.Control.QuerySession_scriptblock_Completed){
        $syncHash.Control.QuerySession_scriptblock_Completed = $false
        $syncHash.Gui.btn_Session.IsEnabled = $true
        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }
    if($syncHash.Control.BSOD_scriptblock_Connected){
        $syncHash.Control.BSOD_scriptblock_Connected = $false

        $syncHash.Gui.btn_Analyze.IsEnabled     = $true
        $syncHash.Gui.cb_AutoReboot.IsEnabled   = $true
        $syncHash.Gui.cb_SysLog.IsEnabled       = $true
        $syncHash.Gui.cb_Overwrite.IsEnabled    = $true
        $syncHash.Gui.btn_GetConfig.IsEnabled   = $true
        $syncHash.Gui.cb_RecoveryConf.IsEnabled = $true
        $syncHash.Gui.btn_ApplyChange.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }
    if($syncHash.Control.System_Recovery_Configuration_Completed){
        $syncHash.Control.System_Recovery_Configuration_Completed = $false

        $syncHash.Gui.btn_Analyze.IsEnabled     = $true
        $syncHash.Gui.cb_AutoReboot.IsEnabled   = $true
        $syncHash.Gui.cb_SysLog.IsEnabled       = $true
        $syncHash.Gui.cb_Overwrite.IsEnabled    = $true
        $syncHash.Gui.btn_GetConfig.IsEnabled   = $true
        $syncHash.Gui.cb_RecoveryConf.IsEnabled = $true
        $syncHash.Gui.btn_ApplyChange.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.ISS_scriptblock_completed){
        $syncHash.control.ISS_scriptblock_completed = $false
        $syncHash.Gui.ISS.IsEnabled = $true
        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.GetInstalledUpdates_scriptblock_completed){
        $syncHash.control.GetInstalledUpdates_scriptblock_completed = $false

        $syncHash.Gui.IU.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.LocalAppList_scriptblock_completed){
        $syncHash.control.LocalAppList_scriptblock_completed = $false

        $syncHash.Gui.AL.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.check_scriptblock_completed) {
        $syncHash.control.check_scriptblock_completed = $false
        
        $syncHash.Gui.Ping_Status.foreground = $syncHash.ping_color
        $syncHash.Gui.Ping_Status.Content = $syncHash.ping_text

        $syncHash.Gui.permission.foreground = $syncHash.permission_color
        $syncHash.Gui.permission.Content = $syncHash.permission_text

        $syncHash.Gui.RDP_enabled.foreground = $syncHash.rdp_color
        $syncHash.Gui.RDP_enabled.Content= $syncHash.rdp_text
        $syncHash.Gui.Uptime.Content = $syncHash.uptime_text
        $syncHash.Gui.btn_Check.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.grant_scriptblock_completed) {
        $syncHash.control.grant_scriptblock_completed = $false

        $syncHash.Gui.btn_Load.IsEnabled   = $true
        $syncHash.Gui.btn_clr.IsEnabled    = $true
        $syncHash.Gui.btn_Add.IsEnabled    = $true
        $syncHash.Gui.btn_Grant.IsEnabled  = $true
        $syncHash.Gui.btn_Remove.IsEnabled = $true
        $syncHash.Gui.btn_List.IsEnabled   = $true
        $syncHash.Gui.btn_Reset.IsEnabled  = $true
        $syncHash.Gui.btn_Test.IsEnabled   = $true
        
        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }
    if($syncHash.control.sList_scriptblock_completed){
        $syncHash.control.sList_scriptblock_completed = $false

        $syncHash.GUI.btn_SoftwareList.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.scan_scriptblock_completed){
        $syncHash.control.scan_scriptblock_completed = $false

        $syncHash.GUI.btn_Scan.IsEnabled = $true
        $syncHash.GUI.btn_Ping.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.ListServices_scriptblock_completed){
        $syncHash.control.ListServices_scriptblock_completed = $false

        $syncHash.Gui.btn_sStart.IsEnabled   = $true
        $syncHash.Gui.btn_sStop.IsEnabled    = $true
        $syncHash.Gui.btn_sRestart.IsEnabled = $true
        $syncHash.Gui.btn_sList.IsEnabled    = $true
        $syncHash.Gui.btn_sQuery.IsEnabled   = $true
        $syncHash.Gui.btn_sChange.IsEnabled  = $tree

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.Firewall_scriptblock_completed) {
        $syncHash.control.Firewall_scriptblock_completed = $false

        $syncHash.Gui.btn_fe1.IsEnabled   = $true
        $syncHash.Gui.btn_fe2.IsEnabled   = $true
        $syncHash.Gui.btn_fe3.IsEnabled   = $true
        $syncHash.Gui.btn_fd1.IsEnabled   = $true
        $syncHash.Gui.btn_fd2.IsEnabled   = $true
        $syncHash.Gui.btn_fd3.IsEnabled   = $true
        $syncHash.Gui.btn_fc1.IsEnabled   = $true
        $syncHash.Gui.btn_fc2.IsEnabled   = $true
        $syncHash.Gui.btn_fc3.IsEnabled   = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.sccm_scriptblock_completed){
        $syncHash.control.sccm_scriptblock_completed = $false

        $syncHash.Gui.btn_sccmUpdate.IsEnabled   = $true
        $syncHash.Gui.btn_sccmStatus.IsEnabled   = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.DeleteProfile_Scriptblock_completed){
        $syncHash.control.DeleteProfile_Scriptblock_completed = $false

        $syncHash.Gui.btn_UPAdd.IsEnabled    = $true
        $syncHash.Gui.btn_UPDelete.IsEnabled = $true
        $syncHash.Gui.btn_UPList.IsEnabled   = $true
        $syncHash.Gui.btn_UPClear.IsEnabled  = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.TestPendingReboot_Scriptblock_completed){
        $syncHash.control.TestPendingReboot_Scriptblock_completed = $false

        $syncHash.GUI.btn_PendingReboot.IsEnabled = $true
        $syncHash.GUI.btn_Reboot.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.Who_scriptblock_completed){
        $syncHash.control.Who_scriptblock_completed = $false

        $syncHash.Gui.btn_Who.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.EnablePSRemoting_scriptblock_completed){
        $syncHash.control.EnablePSRemoting_scriptblock_completed = $false

        $syncHash.Gui.btn_Enable.IsEnabled   = $true
        $syncHash.Gui.btn_TestPSR.IsEnabled  = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.Service_scriptblock_completed) {
        $syncHash.control.Service_scriptblock_completed = $false

        $syncHash.Gui.btn_sStart.IsEnabled   = $true
        $syncHash.Gui.btn_sStop.IsEnabled    = $true
        $syncHash.Gui.btn_sRestart.IsEnabled = $true
        $syncHash.Gui.btn_sList.IsEnabled    = $true
        $syncHash.Gui.btn_sQuery.IsEnabled   = $true
        $syncHash.Gui.btn_sChange.IsEnabled  = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.Hardware_scriptblock_completed) {
        $syncHash.control.Hardware_scriptblock_completed = $false

        $syncHash.Gui.btn_RAM.IsEnabled      = $true
        $syncHash.Gui.btn_BIOS.IsEnabled     = $true
        $syncHash.Gui.btn_Computer.IsEnabled = $true
        $syncHash.Gui.btn_BadHW.IsEnabled    = $true
        $syncHash.Gui.btn_Drive.IsEnabled    = $true
        $syncHash.Gui.btn_Share.IsEnabled    = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.GetBitLockerKey_scriptblock_completed) {
        $syncHash.control.GetBitLockerKey_scriptblock_completed = $false

        $syncHash.Gui.btn_BLKey.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.SuspendBitlocker_scriptblock_completed) {
        $syncHash.control.SuspendBitlocker_scriptblock_completed = $false

        $syncHash.Gui.btn_BLSuspend.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }
    if($syncHash.control.UAC_scriptblock_completed){
        $syncHash.control.UAC_scriptblock_completed = $false

        $syncHash.Gui.btn_UACEnable.IsEnabled  = $true
        $syncHash.Gui.btn_UACDisable.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }
    if($syncHash.control.Process_scriptblock_completed){
        $syncHash.control.Process_scriptblock_completed = $false

        $syncHash.Gui.btn_SearchProc.IsEnabled = $true
        $syncHash.Gui.btn_ListProc.IsEnabled   = $true
        $syncHash.Gui.btn_KillProc.IsEnabled   = $true
        $syncHash.Gui.btn_KillMore.IsEnabled   = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }
    if($syncHash.control.Uninstall_scriptblock_completed){
        $syncHash.control.Uninstall_scriptblock_completed = $false

        $syncHash.Gui.btn_SearchApp.IsEnabled   = $true
        $syncHash.Gui.btn_Uninstall.IsEnabled   = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.network_scriptblock_Connected){
        $syncHash.control.network_scriptblock_Connected = $false

        $syncHash.Gui.btn_Adapters.IsEnabled = $true
        $syncHash.Gui.btn_IPConf.IsEnabled   = $true
        $syncHash.Gui.btn_IPConfig.IsEnabled = $true
        $syncHash.Gui.btn_Tracert.IsEnabled  = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.getBitLockerRecoveryKey_scriptblock_Completed){
        $syncHash.control.getBitLockerRecoveryKey_scriptblock_Completed = $false

        $syncHash.Gui.btn_rGet.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.control.user_detail_scriptblock_completed){
        $syncHash.control.user_detail_scriptblock_completed = $false

        $syncHash.Gui.btn_UserSearch.IsEnabled = $true
        $syncHash.Gui.btn_pwReset.IsEnabled    = $true
        $syncHash.Gui.btn_pwTest.IsEnabled     = $true
        $syncHash.Gui.btn_Unlock.IsEnabled     = $true
        $syncHash.Gui.btn_Detail.IsEnabled     = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.Control.WPK_scriptblock_Completed){
        $syncHash.Control.WPK_scriptblock_Completed = $false

        $syncHash.Gui.WPK.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.Control.InstallDCPP_scriptblock_Completed){
        $syncHash.Control.InstallDCPP_scriptblock_Completed = $false

        $syncHash.Gui.btn_InstallDCPP.IsEnabled  = $true
        $syncHash.Gui.cb_DellSMBIOS.IsEnabled    = $true
        $syncHash.Gui.btn_ListCatagory.IsEnabled = $true
        $syncHash.Gui.btn_Get.IsEnabled          = $true
        $syncHash.Gui.btn_Set.IsEnabled          = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.Control.DellSMBIOS_Get_Item_scriptblock_Completed){
        $syncHash.Control.DellSMBIOS_Get_Item_scriptblock_Completed = $false

        $syncHash.Gui.btn_InstallDCPP.IsEnabled  = $true
        $syncHash.Gui.cb_DellSMBIOS.IsEnabled    = $true
        $syncHash.Gui.btn_ListCatagory.IsEnabled = $true
        $syncHash.Gui.btn_Get.IsEnabled          = $true
        $syncHash.Gui.btn_Set.IsEnabled          = $true

        $syncHash.Gui.cb_Attributes.Items.clear()

        $syncHash.AttributeList | ForEach-Object {
            $syncHash.Gui.cb_Attributes.Items.Add($_)
        }

        $syncHash.Gui.cb_Attributes.SelectedIndex = 0

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.Control.DellSMBIOS_Set_Item_scriptblock_Completed){
        $syncHash.Control.DellSMBIOS_Set_Item_scriptblock_Completed = $false

        $syncHash.Gui.btn_InstallDCPP.IsEnabled  = $true
        $syncHash.Gui.cb_DellSMBIOS.IsEnabled    = $true
        $syncHash.Gui.btn_ListCatagory.IsEnabled = $true
        $syncHash.Gui.btn_Get.IsEnabled          = $true
        $syncHash.Gui.btn_Set.IsEnabled          = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.Control.DellSMBIOS_Catagory_List_Ready){
        $syncHash.Control.DellSMBIOS_Catagory_List_Ready = $false

        $syncHash.Gui.cb_DellSMBIOS.Items.clear()
        $syncHash.Gui.cb_Attributes.Items.clear()

        $syncHash.CatagoryList | ForEach-Object {
            $syncHash.Gui.cb_DellSMBIOS.Items.Add($_)
        }

        $syncHash.Gui.cb_DellSMBIOS.SelectedIndex = 0

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.Control.HP_BIOS_List_Ready){
        $syncHash.Control.HP_BIOS_List_Ready = $false

        $syncHash.Gui.cb_HPBIOSVersions.Items.clear()

        $syncHash.HPBIOSList | ForEach-Object {
            $syncHash.Gui.cb_HPBIOSVersions.Items.Add($_)
        }

        $syncHash.Gui.cb_HPBIOSVersions.SelectedIndex = 0

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.Control.HPCMSL_scriptblock_Completed){
        $syncHash.Control.HPCMSL_scriptblock_Completed = $false

        $syncHash.Gui.btn_HPCMSL.IsEnabled        = $true
        $syncHash.Gui.tb_att.IsEnabled            = $true
        $syncHash.Gui.tb_val.IsEnabled            = $true
        $syncHash.Gui.btn_HpGet.IsEnabled         = $true
        $syncHash.Gui.btn_HpSet.IsEnabled         = $true
        $syncHash.Gui.pb_HpBiosAdminPsw.IsEnabled = $true
        $syncHash.Gui.pb_HpBiosSysPsw.IsEnabled   = $true
        $syncHash.Gui.btn_HpList.IsEnabled        = $true
        $syncHash.Gui.btn_HpClear.IsEnabled       = $true
        $syncHash.Gui.cb_HPBIOSVersions.IsEnabled = $true
        $syncHash.Gui.btn_HpBiosFlash.IsEnabled   = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }

    if($syncHash.Control.MonitorInfo_scriptblock_Completed){
        $syncHash.Control.MonitorInfo_scriptblock_Completed = $false

        $syncHash.Gui.btn_Monitors.IsEnabled = $true

        if(!(isThreadRunning)){ $syncHash.Gui.PB.IsIndeterminate = $false }
    }
}

$syncHash.target_changed = {
    if($syncHash.timer_ping){
        $syncHash.timer_ping.Stop() 2>$null
    }
    $syncHash.Gui.img_LED.source = $null
    $syncHash.Gui.cb_HPBIOSVersions.Items.clear()
    $syncHash.Gui.cb_DellSMBIOS.Items.clear()
    $syncHash.Gui.cb_Attributes.Items.clear()
}

$syncHash.Gui.cb_target.AddHandler([System.Windows.Controls.Primitives.TextBoxBase]::TextChangedEvent, [System.Windows.RoutedEventHandler]$syncHash.target_changed)

# CIDR input validation
$syncHash.Gui.TB_NS_CIDR.Add_TextChanged({
    if ($this.Text -match '[^0-9]') {
        $cursorPos = $this.SelectionStart
        $this.Text = $this.Text -replace '[^0-9]',''
        # move the cursor to the end of the text:
        # $this.SelectionStart = $this.Text.Length

        # or leave the cursor where it was before the replace
        $this.SelectionStart = $cursorPos - 1
        $this.SelectionLength = 0
    }

    $syncHash.Gui.rb_NS_CIDR.IsChecked = $true
})

# IP input validation
$syncHash.Gui.TB_NS_IP.Add_TextChanged({
    if ($this.Text -match '[^0-9.]') {
        $cursorPos = $this.SelectionStart
        $this.Text = $this.Text -replace '[^0-9.]',''
        # move the cursor to the end of the text:
        #$this.SelectionStart = $this.Text.Length

        # or leave the cursor where it was before the replace
        $this.SelectionStart = $cursorPos - 1
        $this.SelectionLength = 0
    }
})

# Network Mask input validation
$syncHash.Gui.TB_NS_Mask.Add_TextChanged({
    if ($this.Text -match '[^0-9.]') {
        $cursorPos = $this.SelectionStart
        $this.Text = $this.Text -replace '[^0-9.]',''
        # move the cursor to the end of the text:
        #$this.SelectionStart = $this.Text.Length

        # or leave the cursor where it was before the replace
        $this.SelectionStart = $cursorPos - 1
        $this.SelectionLength = 0
    }

    $syncHash.Gui.rb_NS_Mask.IsChecked = $true
})

# Threshold input validation
$syncHash.Gui.NS_Threshold.Add_TextChanged({
    if ($this.Text -match '[^0-9]') {
        $cursorPos = $this.SelectionStart
        $this.Text = $this.Text -replace '[^0-9]',''
        # move the cursor to the end of the text:
        # $this.SelectionStart = $this.Text.Length

        # or leave the cursor where it was before the replace
        $this.SelectionStart = $cursorPos - 1
        $this.SelectionLength = 0
    }
})

# Battery  input validation
$syncHash.Gui.tb_DC.Add_TextChanged({
    if ($this.Text -match '[^0-9]') {
        $cursorPos = $this.SelectionStart
        $this.Text = $this.Text -replace '[^0-9]',''
        # move the cursor to the end of the text:
        # $this.SelectionStart = $this.Text.Length

        # or leave the cursor where it was before the replace
        $this.SelectionStart = $cursorPos - 1
        $this.SelectionLength = 0
    }
})

# TCP Port input validation
$syncHash.Gui.NS_TCP_Port.Add_TextChanged({
    if ($this.Text -match '[^0-9]') {
        $cursorPos = $this.SelectionStart
        $this.Text = $this.Text -replace '[^0-9]',''
        # move the cursor to the end of the text:
        # $this.SelectionStart = $this.Text.Length

        # or leave the cursor where it was before the replace
        $this.SelectionStart = $cursorPos - 1
        $this.SelectionLength = 0
    }
})

# check if there is any thread still running
Function isThreadRunning {
    $Queue = 0

    foreach($Job in $syncHash.Jobs){
        $Queue += if ($Job.Handle.IsCompleted -eq $false) { 1 } else { 0 }
    }

    if ($Queue -gt 0){
        return $true
    }

    return $false
}

# check if a thread is still running when exiting the GUI
$syncHash.Window.add_closing({
    [bool]$running = isThreadRunning
    if($running){
        [Windows.MessageBox]::Show(' Worker thread(s) running, please wait...',' Oops!','Ok','Error')
        # the event object is automatically passed through as $_
        $_.Cancel = $true
        return
    }

    # Cleanup mutex
    if($Global:mutex){
        $Global:mutex.Close() 2>$null
        $Global:mutex.Dispose() 2>$null
    }

    # Stop the timer
    if($syncHash.timer){
        $syncHash.timer.Stop() 2>$null
    }
    if($syncHash.timer_terminal){
        $syncHash.timer_terminal.Stop() 2>$null
    }
    if($syncHash.timer_ping){
        $syncHash.timer_ping.Stop() 2>$null
    }

    # Get rid of all global variables
    Remove-Variable -Name "emoji_angry" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_sad" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_Laugh" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_cry" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_pout" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_fear" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_error" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_check" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_tree" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_hand" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_Flower" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_Wait" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_Caution" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_Stop" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_gCheck" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_gError" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_Question" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_eMark" -Scope "Global" 2>$null
    Remove-Variable -Name "emoji_Star" -Scope "Global" 2>$null
    Remove-Variable -Name "createdNew" -Scope "Global" 2>$null
    Remove-Variable -Name "mutex" -Scope "Global" 2>$null
    Remove-Variable -Name "reader" -Scope "Global" 2>$null
    Remove-Variable -Name "xaml" -Scope "Global" 2>$null
})

# Clean up the runspaces when exiting the GUI
$syncHash.Window.add_closed({
    foreach($Job in $syncHash.Jobs)
    {
        if ($Job.Handle.IsCompleted -eq $true)
        {
            $Job.Session.EndInvoke($Job.Handle)
        }
        $RunspacePool.Close()
    }
})

# Exit menu item clicked
$syncHash.GUI.Exit_App.Add_Click({
    $syncHash.Window.close()
})

# Start control panel
$syncHash.GUI.CP.Add_Click({
    try{
        Start-Process -FilePath "control.exe" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0007]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

# Computer management
$syncHash.GUI.CM.Add_Click({
    try{
        Start-Process -FilePath "compmgmt.msc" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0008]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

# services
$syncHash.GUI.SV.Add_Click({
    try{
        Start-Process -FilePath "services.msc" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0009]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

# Device manager
$syncHash.GUI.DM.Add_Click({
    try{
        Start-Process -FilePath "devmgmt.msc" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0010]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.LocalAppList_scriptblock = {
    $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*"

    [System.Collections.Generic.List[string]]$list = Get-ItemProperty -Path $key 2>$null | Select-Object -ExpandProperty '(Default)' -ErrorAction Ignore 2>$null
    [System.Collections.Generic.List[string]]$commands = Get-Command -CommandType Application | Select-Object -ExpandProperty Source 2>$null

    $list.AddRange($commands)

    $finalList = $list | 
        Where-Object { $_ } |
        ForEach-Object { $_.Replace('"','').Trim().ToLower() } |
        Sort-Object -Unique |
        ForEach-Object {
            try {
                $file = Get-Item -Path $_ -ErrorAction Ignore 2>$null
                [PSCustomObject]@{
                    Name = $file.Name
                    Description = $file.VersionInfo.FileDescription
                    Path = $file.FullName
                }
            } catch {}
        } | Sort-Object -Property Name -Unique 

    $finalList | Out-GridView -Title "Application list on $env:COMPUTERNAME"

    Remove-Variable -Name "key" 2>$null
    Remove-Variable -Name "list" 2>$null
    Remove-Variable -Name "commands" 2>$null
    Remove-Variable -Name "finalList" 2>$null
    Remove-Variable -Name "file" 2>$null

    $syncHash.control.LocalAppList_scriptblock_completed = $true
}

# Local application list
$syncHash.GUI.AL.Add_Click({
    # Disable wedgets
    $syncHash.Gui.AL.IsEnabled = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.LocalAppList_scriptblock)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GetInstalledUpdates_scriptblock = {
    $severity = @{
        Name = 'Severity'
        Expression = { if ([string]::IsNullOrEmpty($_.MsrcSeverity)) { 'normal' } else { $_.MsrcSeverity }}
    }

    $time = @{
        Name = 'Time'
        Expression = { $_.LastDeploymentChangeTime }
    }

    $kb = @{
        Name = 'KB'
        Expression = { if ($_.Title -match 'KB\d{6,9}') { $matches[0] } else { 'N/A' }}
    }

    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSession.CreateupdateSearcher().Search("IsInstalled=1").Updates | Select-Object $time, Title, $kb, Description, $Severity | Out-GridView -Title "Installed Updates on $env:COMPUTERNAME"

    Remove-Variable -Name "severity" 2>$null
    Remove-Variable -Name "time" 2>$null
    Remove-Variable -Name "kb" 2>$null
    Remove-Variable -Name "UpdateSession" 2>$null

    $syncHash.control.GetInstalledUpdates_scriptblock_completed = $true
}

$syncHash.GUI.IU.Add_Click({
    # Disable wedgets
    $syncHash.Gui.IU.IsEnabled = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.GetInstalledUpdates_scriptblock)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GUI.SYS.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0011]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    msinfo32.exe /computer $cn
})

$syncHash.GUI.btn_SoftwareInfo.Add_Click({
    start-process powershell -WindowStyle Hidden -ArgumentList ".\System_Explorer.ps1"
})

$syncHash.GUI.QA.Add_Click({
    quickassist.exe
})

$syncHash.Share_scriptblock = {
    param(
        [string]$cn,
        [bool]$remote
    )

    if($remote){
        $Share = Get-WmiObject -Class Win32_Share -ComputerName $cn 2>$null 3>$null
        if(!($Share)){
            $e = "[Error 0012]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            $msg = "The RPC is not available on $cn."
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
        $msg = "Shared resouces on $cn :"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow",$msg,$true
    } else {
        $Share = Get-WmiObject -Class Win32_Share
        if(!($Share)){
            $e = "[Error 0013]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            $msg = "The RPC is not available on LocalHost."
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
        $msg = "Shared resouces on LOCALHOST :"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow",$msg,$true
    }

    [int]$CaptionPad = 0
    [int]$NamePad = 0
    [int]$StatusPad = 0
    [int]$PathPad = 0
    [int]$DescriptionPad = 0
    
    $Share | ForEach-Object {
        if(($_.Caption).Length -ge $CaptionPad){
            $CaptionPad = ($_.Caption).Length + 2
        }
        if(($_.Name).Length -ge $NamePad){
            $NamePad = ($_.Name).Length + 2
        }
        if(($_.Status).Length -ge $StatusPad){
            $StatusPad = ($_.Status).Length + 2
        }
        if(($_.Path).Length -ge $PathPad){
            $PathPad = ($_.Path).Length + 2
        }
    }
    if($CaptionPad -le 7) {$CaptionPad = 9}
    if($NamePad -le 4) {$NamePad = 6}
    if($StatusPad -le 6) {$StatusPad = 8}
    if($PathPad -le 4) {$PathPad = 6}

    $msg = ("Caption").PadRight($CaptionPad) + ("Name").PadRight($NamePad) + ("Status").PadRight($StatusPad) + ("Path").PadRight($PathPad) + ("Description").PadRight($DescriptionPad)
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$msg,$true
    [int]$i = 0
    $Share | ForEach-Object {
        $a = ($_.Caption).PadRight($CaptionPad)
        $b = ($_.Name).PadRight($NamePad)
        $c = ($_.Status).PadRight($StatusPad)
        $d = ($_.Path).PadRight($PathPad)
        $e = $_.Description
        $msg = $a + $b + $c + $d + $e
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$true

        $i++
    }
    $msg = "Total $i share(s) found."
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$msg,$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "share" 2>$null
    Remove-Variable -Name "msg" 2>$null
    Remove-Variable -Name "CaptionPad" 2>$null
    Remove-Variable -Name "StatusPad" 2>$null
    Remove-Variable -Name "NamePad" 2>$null
    Remove-Variable -Name "PathPad" 2>$null
    Remove-Variable -Name "DescriptionPad" 2>$null
    Remove-Variable -Name "i" 2>$null
    Remove-Variable -Name "a" 2>$null
    Remove-Variable -Name "b" 2>$null
    Remove-Variable -Name "c" 2>$null
    Remove-Variable -Name "d" 2>$null
    Remove-Variable -Name "e" 2>$null

    $syncHash.control.Hardware_scriptblock_completed = $true
}

$syncHash.GUI.btn_Share.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$remote = $false

    if([string]::IsNullOrEmpty($cn)){
        $remote = $false
    } else {
        # Ping test
        try {
            $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
        } catch {
            $e = "[Error 0014]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            return
        }

        if(!$test){
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
            return
        }
        $remote = $true
        if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
            $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
        }
    }

    # Disable wedgets
    $syncHash.Gui.btn_RAM.IsEnabled      = $false
    $syncHash.Gui.btn_BIOS.IsEnabled     = $false
    $syncHash.Gui.btn_Computer.IsEnabled = $false
    $syncHash.Gui.btn_BadHW.IsEnabled    = $false
    $syncHash.Gui.btn_Drive.IsEnabled    = $false
    $syncHash.Gui.btn_Share.IsEnabled    = $false

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.Share_scriptblock).AddArgument($cn).AddArgument($remote)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.Drive_scriptblock = {
    param(
        [string]$cn,
        [bool]$remote
    )

    if($remote){
        $drive = Get-WmiObject -Class Win32_DiskDrive -ComputerName $cn 2>$null 3>$null
        if(!($drive)){
            $e = "[Error 0015]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            $msg = "The RPC is not available on $cn."
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
        $msg = "Drive information on $cn :"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow",$msg,$true
    } else {
        $drive = Get-WmiObject -Class Win32_DiskDrive
        if(!($drive)){
            $e = "[Error 0016]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            $msg = "The RPC is not available on LocalHost."
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
        $msg = "Drive information on LOCALHOST :"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow",$msg,$true
    }

    [int]$CaptionPad = 0
    [int]$DescriptionPad = 0
    [int]$NamePad = 0
    [int]$StatusPad = 0
    [int]$InterfacePad = 0
    [int]$ModelPad = 0
    [int]$SizePad = 0
    
    $drive | ForEach-Object {
        if(($_.Caption).Length -ge $CaptionPad){
            $CaptionPad = ($_.Caption).Length + 2
        }
        if(($_.Description).Length -ge $DescriptionPad){
            $DescriptionPad = ($_.Description).Length + 2
        }
        if(($_.Name).Length -ge $NamePad){
            $NamePad = ($_.Name).Length + 2
        }
        if(($_.Status).Length -ge $StatusPad){
            $StatusPad = ($_.Status).Length + 2
        }
        if(($_.InterfaceType).Length -ge $InterfacePad){
            $InterfacePad = ($_.InterfaceType).Length + 2
        }
        if(($_.Model).Length -ge $ModelPad){
            $ModelPad = ($_.Model).Length + 2
        }
        if(($_.Size).Length -ge $SizePad){
            $SizePad = ([math]::round((($_.Size)/1024/1024/1024)).ToString() + " GB").length + 2
        }
    }
    if($CaptionPad -le 7) {$CaptionPad = 9}
    if($DescriptionPad -le 11) {$CaptionPad = 13}
    if($NamePad -le 4) {$NamePad = 6}
    if($StatusPad -le 6) {$StatusPad = 8}
    if($InterfacePad -le 9) {$InterfacePad = 11}
    if($ModelPad -le 5) {$ModelPad = 7}
    if($SizePad -le 4) {$SizePad = 6}
    $msg = ("Caption").PadRight($CaptionPad) + ("Description").PadRight($DescriptionPad) + ("Status").PadRight($StatusPad) + ("Size").PadRight($SizePad) + ("Interface").PadRight($InterfacePad) + ("Model").PadRight($ModelPad) + "SerialNumber"
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$msg,$true
    [int]$i = 0
    $drive | ForEach-Object {
        $a = ($_.Caption).PadRight($CaptionPad)
        $b = ($_.Description).PadRight($DescriptionPad)
        $c = ($_.Status).PadRight($StatusPad)
        $d = (([math]::round((($_.Size)/1024/1024/1024)).ToString()) + " GB").PadRight($SizePad)
        $e = ($_.InterfaceType).PadRight($InterfacePad)
        $f = (($_.Model).trim()).PadRight($ModelPad)
        $g = ($_.SerialNumber).trim()
        $msg = $a + $b + $c + $d + $e + $f + $g
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$true

        $i++
    }
    $msg = "Total $i disk(s) found."
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$msg,$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "drive" 2>$null
    Remove-Variable -Name "e" 2>$null
    Remove-Variable -Name "msg" 2>$null
    Remove-Variable -Name "CaptionPad" 2>$null
    Remove-Variable -Name "DescriptionPad" 2>$null
    Remove-Variable -Name "NamePad" 2>$null
    Remove-Variable -Name "StatusPad" 2>$null
    Remove-Variable -Name "InterfacePad" 2>$null
    Remove-Variable -Name "ModelPad" 2>$null
    Remove-Variable -Name "SizePad" 2>$null
    Remove-Variable -Name "i" 2>$null
    Remove-Variable -Name "a" 2>$null
    Remove-Variable -Name "b" 2>$null
    Remove-Variable -Name "c" 2>$null
    Remove-Variable -Name "d" 2>$null
    Remove-Variable -Name "e" 2>$null
    Remove-Variable -Name "f" 2>$null
    Remove-Variable -Name "g" 2>$null

    $syncHash.control.Hardware_scriptblock_completed = $true
}

$syncHash.GUI.btn_Drive.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$remote = $false

    if([string]::IsNullOrEmpty($cn)){
        $remote = $false
    } else {
        # Ping test
        try {
            $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
        } catch {
            $e = "[Error 0017]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            return
        }

        if(!$test){
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
            return
        }
        $remote = $true
        if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
            $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
        }
    }

    # Disable wedgets
    $syncHash.Gui.btn_RAM.IsEnabled      = $false
    $syncHash.Gui.btn_BIOS.IsEnabled     = $false
    $syncHash.Gui.btn_Computer.IsEnabled = $false
    $syncHash.Gui.btn_BadHW.IsEnabled    = $false
    $syncHash.Gui.btn_Drive.IsEnabled    = $false
    $syncHash.Gui.btn_Share.IsEnabled    = $false

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.Drive_scriptblock).AddArgument($cn).AddArgument($remote)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.Computer_scriptblock = {
    param(
        [string]$cn,
        [bool]$remote,
        [pscredential]$cred
    )

    if($remote){
        $com = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $cn 2>$null 3>$null
        if(!($com)){
            $e = "[Error 0018]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            $msg = "The RPC is not available on $cn."
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
        $msg = "Computer information on $cn :"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow",$msg,$true
    } else {
        $com = Get-WmiObject -Class Win32_ComputerSystem
        if(!($com)){
            $e = "[Error 0019]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            $msg = "The RPC is not available on LocalHost."
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
        $msg = "Computer information on LOCALHOST :"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow",$msg,$true
    }

    [int]$pad = 23
    if($com.Caption){
        $msg = ("Caption").PadRight($pad) + ": " + $com.Caption
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.Name){
        $msg = ("Name").PadRight($pad) + ": " + $com.Name
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.Manufacturer){
        $msg = ("Manufacturer").PadRight($pad) + ": " + $com.Manufacturer
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.Model){
        $msg = ("Model").PadRight($pad) + ": " + $com.Model
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.Domain){
        $msg = ("Domain").PadRight($pad) + ": " + $com.Domain
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.PrimaryOwnerName){
        $msg = ("PrimaryOwnerName").PadRight($pad) + ": " + $com.PrimaryOwnerName
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.TotalPhysicalMemory){
        $msg = ("TotalPhysicalMemory").PadRight($pad) + ": " + [math]::Round((($com.TotalPhysicalMemory)/(1024*1024*1024))).ToString() + " GB"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.DNSHostName){
        $msg = ("DNSHostName").PadRight($pad) + ": " + $com.DNSHostName
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.Description){
        $msg = ("Description").PadRight($pad) + ": " + $com.Description
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.NumberOfProcessors){
        $msg = ("NumberOfProcessors").PadRight($pad) + ": " + ($com.NumberOfProcessors).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.NumberOfLogicalProcessors){
        $msg = ("LogicalProcessors").PadRight($pad) + ": " + ($com.NumberOfLogicalProcessors).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.Status){
        $msg = ("Status").PadRight($pad) + ": " + $com.Status
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.Username){
        $msg = ("Username").PadRight($pad) + ": " + $com.Username
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.PSComputerName){
        $msg = ("PSComputerName").PadRight($pad) + ": " + $com.PSComputerName
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.HypervisorPresent){
        $msg = ("HypervisorPresent").PadRight($pad) + ": " + ($com.HypervisorPresent).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.SystemSKUNumber){
        $msg = ("SystemSKUNumber").PadRight($pad) + ": " + $com.SystemSKUNumber
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.SystemType){
        $msg = ("SystemType").PadRight($pad) + ": " + $com.SystemType
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($com.ThermalState){
        switch ($com.ThermalState)
        {
            1  {$a = "Other"; $color = "Orange"}
            2  {$a = "Unknown"; $color = "Orange"}
            3  {$a = "Safe"; $color = "Lime"}
            4  {$a = "Warning"; $color = "Orange"}
            5  {$a = "Critical"; $color = "Red"}
            6  {$a = "Non-recoverable"; $color = "Red"}
        }
        $msg = ("ThermalState").PadRight($pad) + ": "
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$false
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20",$color,$a,$true
    }

    if(($cn -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") -and ($cn -as [IPAddress] -as [Bool])) {
        # IP address provided
        $hsEntry = [System.Net.Dns]::GetHostEntry($cn)
        if($hsEntry){
            $hn = (($hsEntry.HostName).Split('.'))[0]
        }
    } else {
        $hn = $cn
    }
    if($hn){
        [string]$OU = ""    
        $filter = "(&(objectCategory=computer)(objectClass=computer)(cn=$hn))"    
        $a=([adsisearcher]$filter).FindOne().Properties.distinguishedname | Out-String
        if($a){
            $b=$a.split(',')    
            for([int]$i=$b.count-1;$i -ge 0;$i--){    
                $c = $b[$i].Split('=')    
                if($c[0] -eq "DC") {    
                    $d = $c[1].Trim()    
                    $OU = $d + "\" + $OU    
                } else {    
                    $d = $c[1].Trim()    
                    if($i -eq 0){    
                        $OU = $OU + $d    
                    } else {    
                        $OU = $OU + $d + "\"    
                    }    
                }    
                Remove-Variable -Name "c"    
            }    
            $msg = ("OU").PadRight($pad) + ": " + $OU    
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
        }
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    if($remote){
        $v = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $cn 2>$null 3>$null
        $dv = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock {
            $d = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion
            $d
        }
    }else{
        $v = Get-WmiObject -Class Win32_OperatingSystem 2>$null 3>$null
        $dv = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","=== OS Version Info ===",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","Caption         : ",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$v.Caption,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","Name            : ",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$v.Name,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","Display Version : ",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$dv,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","Version         : ",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$v.Version,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","BuildNumber     : ",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$v.BuildNumber,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","Organization    : ",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$v.Organization,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","RegisteredUser  : ",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$v.RegisteredUser,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","OSArchitecture  : ",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$v.OSArchitecture,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","MUILanguages    : ",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$v.MUILanguages,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","SystemDevice    : ",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$v.SystemDevice,$true

    Remove-Variable -Name "com" 2>$null
    Remove-Variable -Name "e" 2>$null
    Remove-Variable -Name "msg" 2>$null
    Remove-Variable -Name "pad" 2>$null
    Remove-Variable -Name "a" 2>$null
    Remove-Variable -Name "color" 2>$null
    Remove-Variable -Name "hsEntry" 2>$null
    Remove-Variable -Name "hn" 2>$null
    Remove-Variable -Name "OU" 2>$null
    Remove-Variable -Name "filter" 2>$null
    Remove-Variable -Name "b" 2>$null
    Remove-Variable -Name "c" 2>$null
    Remove-Variable -Name "d" 2>$null
    Remove-Variable -Name "v" 2>$null
    Remove-Variable -Name "dv" 2>$null

    $syncHash.control.Hardware_scriptblock_completed = $true
}

$syncHash.GUI.btn_Computer.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$remote = $false

    if([string]::IsNullOrEmpty($cn)){
        $remote = $false
    } else {
        # Ping test
        try {
            $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
        } catch {
            $e = "[Error 0020]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            return
        }

        if(!$test){
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
            return
        }
        $remote = $true
        if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
            $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
        }
    }

    # Disable wedgets
    $syncHash.Gui.btn_RAM.IsEnabled      = $false
    $syncHash.Gui.btn_BIOS.IsEnabled     = $false
    $syncHash.Gui.btn_Computer.IsEnabled = $false
    $syncHash.Gui.btn_BadHW.IsEnabled    = $false
    $syncHash.Gui.btn_Drive.IsEnabled    = $false
    $syncHash.Gui.btn_Share.IsEnabled    = $false

    # create the extra Powershell session and add the script block to execute
    if($remote){
        $Session = [PowerShell]::Create().AddScript($syncHash.Computer_scriptblock).AddArgument($cn).AddArgument($remote).AddArgument($syncHash.PSRemote_credential)
    } else {
        $Session = [PowerShell]::Create().AddScript($syncHash.Computer_scriptblock).AddArgument($env:COMPUTERNAME).AddArgument($remote)
    }

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.BIOS_scriptblock = {
    param(
        [string]$cn,
        [bool]$remote
    )

    if($remote){
        $bios = Get-WmiObject -Class win32_bios -ComputerName $cn 2>$null 3>$null
        if(!($bios)){
            $e = "[Error 0021]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            $msg = "The RPC is not available on $cn."
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
        $msg = "BIOS Configuration on $cn :"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow",$msg,$true
    } else {
        $bios = Get-WmiObject -Class win32_bios
        if(!($bios)){
            $e = "[Error 0022]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            $msg = "The RPC is not available on LocalHost."
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
        $msg = "BIOS Configuration on LOCALHOST :"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow",$msg,$true
    }

    [int]$pad = 23
    $msg = ("Name").PadRight($pad) + ": " + $bios.Name
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    $msg = ("Status").PadRight($pad) + ": "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$false
    $msg = $bios.status
    if($msg -eq "OK") {
        $color = "Cyan"
    } else {
        $color = "Red"
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20",$color,$msg,$true
    if($bios.Caption){
        $msg = ("Caption").PadRight($pad) + ": " + $bios.Caption
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($bios.Description){
        $msg = ("Description").PadRight($pad) + ": " + $bios.Description
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($bios.Manufacturer){
        $msg = ("Manufacturer").PadRight($pad) + ": " + $bios.Manufacturer
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($bios.SerialNumber){
        $msg = ("SerialNumber").PadRight($pad) + ": " + $bios.SerialNumber
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Orange",$msg,$true
    }
    if($bios.Version){
        $msg = ("Version").PadRight($pad) + ": " + $bios.Version
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($bios.SMBIOSBIOSVersion){
        $msg = ("SMBIOSBIOSVersion").PadRight($pad) + ": " + $bios.SMBIOSBIOSVersion
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Lime",$msg,$true
    }
    if($bios.SMBIOSMajorVersion){
        $msg = ("SMBIOSMajorVersion").PadRight($pad) + ": " + ($bios.SMBIOSMajorVersion).ToString()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Lime",$msg,$true
    }
    if($bios.SMBIOSMinorVersion){
        $msg = ("SMBIOSMinorVersion").PadRight($pad) + ": " + ($bios.SMBIOSMinorVersion).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Lime",$msg,$true
    }
    if($bios.SystemBIOSMajorVersion) {
        $msg = ("SystemBIOSMajorVersion").PadRight($pad) + ": " + ($bios.SystemBIOSMajorVersion).ToString()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($bios.SystemBIOSMinorVersion) {
        $msg = ("SystemBIOSMinorVersion").PadRight($pad) + ": " + ($bios.SystemBIOSMinorVersion).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($bios.PrimaryBIOS) {
        $msg = ("PrimaryBIOS").PadRight($pad) + ": " + ($bios.PrimaryBIOS).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($bios.SMBIOSPresent){
        $msg = ("SMBIOSPresent").PadRight($pad) + ": " + ($bios.SMBIOSPresent).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($bios.BIOSVersion){
        $msg = ("BIOSVersion").PadRight($pad) + ": "
        ($bios.BIOSVersion).Split("`n") | ForEach-Object {
            $msg += "$_ "
        }
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($bios.EmbeddedControllerMajorVersion){
        $msg = ("EmbeddedController").PadRight($pad) + ": " + "MajorVersion = " + ($bios.EmbeddedControllerMajorVersion).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($bios.EmbeddedControllerMinorVersion){
        $msg = ("EmbeddedController").PadRight($pad) + ": " + "MinorVersion = " + ($bios.EmbeddedControllerMinorVersion).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    }
    if($bios.ReleaseDate){
        $msg = ("ReleaseDate").PadRight($pad) + ": " + $bios.ConvertToDateTime($bios.ReleaseDate).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Lime",$msg,$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "bios" 2>$null
    Remove-Variable -Name "e" 2>$null
    Remove-Variable -Name "msg" 2>$null
    Remove-Variable -Name "pad" 2>$null
    Remove-Variable -Name "color" 2>$null

    $syncHash.control.Hardware_scriptblock_completed = $true
}

$syncHash.GUI.btn_BIOS.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$remote = $false

    if([string]::IsNullOrEmpty($cn)){
        $remote = $false
    } else {
        # Ping test
        try {
            $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
        } catch {
            $e = "[Error 0023]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            return
        }

        if(!$test){
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
            return
        }
        $remote = $true
        if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
            $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
        }
    }

    # Disable wedgets
    $syncHash.Gui.btn_RAM.IsEnabled      = $false
    $syncHash.Gui.btn_BIOS.IsEnabled     = $false
    $syncHash.Gui.btn_Computer.IsEnabled = $false
    $syncHash.Gui.btn_BadHW.IsEnabled    = $false
    $syncHash.Gui.btn_Drive.IsEnabled    = $false
    $syncHash.Gui.btn_Share.IsEnabled    = $false

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.BIOS_scriptblock).AddArgument($cn).AddArgument($remote)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.RAM_scriptblock = {
    param(
        [string]$cn,
        [bool]$remote
    )

    if($remote){
        $ram = Get-WmiObject -Class Win32_PhysicalMemory -ComputerName $cn 2>$null 3>$null
        if(!($ram)){
            $e = "[Error 0024]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            $msg = "The RPC is not available on $cn."
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
        $msg = "RAM Configuration on $cn :"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow",$msg,$true
    } else {
        $ram = Get-WmiObject -Class Win32_PhysicalMemory
        if(!($ram)){
            $e = "[Error 0025]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            $msg = "The RPC is not available on LocalHost."
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
        $msg = "RAM Configuration on LOCALHOST :"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow",$msg,$true
    }

    [int]$LocationPad = 0
    [int]$ManufacturerPad = 0
    [int]$SpeedPad = 0
    [int]$CapacityPad = 0
    [int]$SerialNumberPad = 0
    [int]$RAMTypePad = 0
    [int]$FormFactorPad = 0

    $ram | ForEach-Object {
        if(($_.DeviceLocator.Trim()).Length -ge $LocationPad){
            $LocationPad = ($_.DeviceLocator.Trim()).Length + 2
        }
        if(($_.Manufacturer.Trim()).Length -ge $ManufacturerPad){
            $ManufacturerPad = ($_.Manufacturer.Trim()).Length + 2
        }
        if(($_.SerialNumber.Trim()).Length -ge $SerialNumberPad){
            $SerialNumberPad = ($_.SerialNumber.Trim()).Length + 2
        }
    }
    if($LocationPad -le 8) {$LocationPad = 10}
    if($ManufacturerPad -le 12) {$ManufacturerPad = 14}
    $SpeedPad = 10
    $CapacityPad = 10
    if($SerialNumberPad -le 12) {$SerialNumberPad = 14}
    $RAMTypePad = 9
    $FormFactorPad = 12
    
    if($PathPad -le 4) {$PathPad = 6}

    $msg = "Location".PadRight($LocationPad) + "Manufacturer".PadRight($ManufacturerPad) + "Speed".PadRight($SpeedPad) + "Capacity".PadRight($CapacityPad) + "SerialNumber".PadRight($SerialNumberPad) + "RAMType".PadRight($RAMTypePad) + "FormFactor".PadRight($FormFactorPad) + "Parity"
    Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text $msg -NewLine $true
    [int]$i = 0
    $ram | ForEach-Object {
        [string]$a = ($_.DeviceLocator).trim()
        $a = $a.PadRight($LocationPad)
        [string]$b = ($_.Manufacturer).trim()
        $b = $b.PadRight($ManufacturerPad)
        if($_.speed){
            [string]$c = ($_.Speed).ToString().trim()
        } else {
            [string]$c = "n/a"
        }
        $c = $c.PadRight($SpeedPad)
        if($_.Capacity){
            $d = (((($_.Capacity)/1024/1024/1024).ToString()).trim() + " GB").PadRight($CapacityPad)
        } else {
            $d = "n/a"
        }
        if($_.SerialNumber){
            $e = ($_.SerialNumber.trim()).PadRight($SerialNumberPad)
        } else {
            $e = "n/a"
        }
        switch ($_.MemoryType)
        {
            0  {$f = "Unknown"}
            1  {$f = "Other"}
            2  {$f = "DRAM"}
            3  {$f = "Synchronous DRAM"}
            4  {$f = "Cache DRAM"}
            5  {$f = "EDO"}
            6  {$f = "EDRAM"}
            7  {$f = "VRAM"}
            8  {$f = "SRAM"}
            9  {$f = "RAM"}
            10 {$f = "ROM"}
            11 {$f = "Flash"}
            12 {$f = "EEPROM"}
            13 {$f = "FEPROM"}
            14 {$f = "EPROM"}
            15 {$f = "CDRAM"}
            16 {$f = "3DRAM"}
            17 {$f = "SDRAM"}
            18 {$f = "SGRAM"}
            19 {$f = "RDRAM"}
            20 {$f = "DDR"}
            21 {$f = "DDR2"}
            22 {$f = "DDR2 FB-DIMM"}
            23 {$f = ""}
            24 {$f = "DDR3"}
            25 {$f = "FBD2"}
            26 {$f = "DDR4"}
        }
        $f = $f.PadRight($RAMTypePad)
        switch ($_.FormFactor)
        {
            0  {$g = "Unknown"}
            1  {$g = "Other"}
            2  {$g = "SIP"}
            3  {$g = "DIP"}
            4  {$g = "ZIP"}
            5  {$g = "SOJ"}
            6  {$g = "Proprietary"}
            7  {$g = "SIMM"}
            8  {$g = "DIMM"}
            9  {$g = "TSOP"}
            10 {$g = "PGA"}
            11 {$g = "RIMM"}
            12 {$g = "SODIMM"}
            13 {$g = "SRIMM"}
            14 {$g = "SMD"}
            15 {$g = "SSMP"}
            16 {$g = "QFP"}
            17 {$g = "TQFP"}
            18 {$g = "SOIC"}
            19 {$g = "LCC"}
            20 {$g = "PLCC"}
            21 {$g = "BGA"}
            22 {$g = "FPBGA"}
            23 {$g = "LGA"}
        }
        $g = $g.PadRight($FormFactorPad)
        if($_.TotalWidth -gt $_.DataWidth) {
            $h = "ECC"
        } else {
            $h = "Non-ECC"
        }
        $msg = $a + $b  + $c + $d + $e + $f + $g + $h
        $i++
        if($i%2 -eq 0){
            $color = "LightGreen"
        } else {
            $color = "Lime"
        }
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18",$color,$msg,$true
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "ram"
    Remove-Variable -Name "msg"
    Remove-Variable -Name "e"
    Remove-Variable -Name "LocationPad"
    Remove-Variable -Name "ManufacturerPad"
    Remove-Variable -Name "SpeedPad"
    Remove-Variable -Name "CapacityPad"
    Remove-Variable -Name "SerialNumberPad"
    Remove-Variable -Name "RAMTypePad"
    Remove-Variable -Name "FormFactorPad"
    Remove-Variable -Name "a"
    Remove-Variable -Name "b"
    Remove-Variable -Name "c"
    Remove-Variable -Name "d"
    Remove-Variable -Name "f"
    Remove-Variable -Name "g"
    Remove-Variable -Name "h"
    Remove-Variable -Name "i"
    Remove-Variable -Name "color"

    $syncHash.control.Hardware_scriptblock_completed = $true
}

$syncHash.GUI.btn_RAM.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$remote = $false

    if([string]::IsNullOrEmpty($cn)){
        $remote = $false
    } else {
        # Ping test
        try {
            $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
        } catch {
            $e = "[Error 0026]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            return
        }

        if(!$test){
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
            return
        }
        $remote = $true
        if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
            $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
        }
    }

    # Disable wedgets
    $syncHash.Gui.btn_RAM.IsEnabled      = $false
    $syncHash.Gui.btn_BIOS.IsEnabled     = $false
    $syncHash.Gui.btn_Computer.IsEnabled = $false
    $syncHash.Gui.btn_BadHW.IsEnabled    = $false
    $syncHash.Gui.btn_Drive.IsEnabled    = $false
    $syncHash.Gui.btn_Share.IsEnabled    = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.RAM_scriptblock).AddArgument($cn).AddArgument($remote)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.BadHardwareList_scriptblock = {
    param (
        [string]$cn,
        [bool]$remote
    )

    # Display Computer details
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Cyan","Computer Details:",$true
    if($remote){
        $comp = Get-WmiObject Win32_ComputerSystem -ComputerName $cn
        if(!($comp)){
            $e = "[Error 0027]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red","The RPC is not available on $cn.",$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
    } else {
        $comp = Get-WmiObject Win32_ComputerSystem
        if(!($comp)){
            $e = "[Error 0028]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red","The RPC is not available on LocalHost.",$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
    }

    $msg = "Manufacturer: {0}" -f $comp.Manufacturer
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    $msg = "Model:        {0}" -f $comp.Model
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true

    if($remote){
        $comp = Get-WmiObject Win32_ComputerSystemProduct -ComputerName $cn
        if(!($comp)){
            $e = "[Error 0029]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red","The RPC is not available on $cn.",$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
    } else {
        $comp = Get-WmiObject Win32_ComputerSystemProduct
        if(!($comp)){
            $e = "[Error 0030]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red","The RPC is not available on LocalHost.",$true
            $syncHash.control.Hardware_scriptblock_completed = $true
            return
        }
    }
    $msg = "SerialNumber: {0}" -f $comp.IdentifyingNumber
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true

    #Get hardware that is errored
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","  ",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","Bad hardware list:",$true

    if($remote){
        $broken = Get-WmiObject Win32_PnPEntity -ComputerName $cn | Where-Object {$_.ConfigManagerErrorCode -ne 0}
    } else {
        $broken = Get-WmiObject Win32_PnPEntity | Where-Object {$_.ConfigManagerErrorCode -ne 0}
    }
    
    #Display broken hardware
    [int]$i = 0
    foreach ($obj in $broken){
        $i++
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","(Item $i)",$true
        $msg = "Description:  {0}" -f  $obj.Description
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$true
        $msg = "Device ID:    {0}" -f  $obj.DeviceID
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$true
        $msg = "Error ID:     {0}" -f  $obj.ConfigManagerErrorCode
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","$i item(s) found.",$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "comp" 2>$null
    Remove-Variable -Name "e" 2>$null
    Remove-Variable -Name "msg" 2>$null
    Remove-Variable -Name "broken" 2>$null
    Remove-Variable -Name "i" 2>$null
    Remove-Variable -Name "obj" 2>$null

    $syncHash.control.Hardware_scriptblock_completed = $true
}

$syncHash.GUI.btn_BadHW.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$remote = $false

    if([string]::IsNullOrEmpty($cn)){
        $remote = $false
    } else {
        # Ping test
        try {
            $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
        } catch {
            $e = "[Error 0031]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            return
        }

        if(!$test){
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
            return
        }
        $remote = $true
        if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
            $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
        }
    }

    # Disable wedgets
    $syncHash.Gui.btn_RAM.IsEnabled      = $false
    $syncHash.Gui.btn_BIOS.IsEnabled     = $false
    $syncHash.Gui.btn_Computer.IsEnabled = $false
    $syncHash.Gui.btn_BadHW.IsEnabled    = $false
    $syncHash.Gui.btn_Drive.IsEnabled    = $false
    $syncHash.Gui.btn_Share.IsEnabled    = $false

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.BadHardwareList_scriptblock).AddArgument($cn).AddArgument($remote)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GetDeviceListRemotely_scriptblock = {
    param (
        [string]$cn
    )

    Get-WmiObject Win32_PnPEntity -ComputerName $cn | Out-GridView -Title "Device list on $cn"
}

# get Device list from remote computer
$syncHash.GUI.Device.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    # If the computer name field is blank, don't do anything
    if([string]::IsNullOrEmpty($cn)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        Remove-Variable -Name "cn"
        Return
    }

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.GetDeviceListRemotely_scriptblock).AddArgument($cn)
    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    Remove-Variable -Name "cn"
})

$syncHash.WPK_scriptblock = {
    param(
        [string]$cn,
        [pscredential]$cred
    )

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","30","Lime","Current PK:",$true

    
    if($cred){
        $key = invoke-command -ComputerName $cn -Credential $cred -ScriptBlock $syncHash.Get_WindowsProductKey 2>$null
    } else {
        $key = invoke-command -ComputerName $cn -ScriptBlock $syncHash.Get_WindowsProductKey 2>$null
    }
    if($key){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","30","Cyan","{",$false
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","30","Orange","$key",$false
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","30","Cyan","}",$true
    } else {
        $e = "[Error 0032]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","30","Orange","Cannot find the key.",$false
        Remove-Variable -Name "e"
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","30","LightGreen","            ",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","30","Lime","Original PK:",$true

    if($cred){
        $key = invoke-command -ComputerName $cn -Credential $cred -ScriptBlock {
            $k = wmic path softwarelicensingservice get OA3xOriginalProductKey | Out-String
            return $k
        }
    } else {
        $key = invoke-command -ComputerName $cn -ScriptBlock {
            $k = wmic path softwarelicensingservice get OA3xOriginalProductKey | Out-String
            return $k
        }
    }
    $key = $key.replace('OA3xOriginalProductKey','').trim()
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","30","Cyan","{",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","30","Orange","$key",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","30","Cyan","}",$true

    Remove-Variable -Name "cn"
    Remove-Variable -Name "key"

    $syncHash.Control.WPK_scriptblock_Completed = $true
}

# Get Windows Product Key from remote computer
$syncHash.GUI.WPK.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    # If the computer name field is blank, don't do anything
    if([string]::IsNullOrEmpty($cn)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        Remove-Variable -Name "cn"
        Return
    }

    # Disable wedgets
    $syncHash.Gui.WPK.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.WPK_scriptblock).AddArgument($cn).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Get Windows Product Key from local machine
$syncHash.GUI.PK.Add_Click({
    Show-Result -Font "Courier New" -Size "30" -Color "LightGreen" -Text "Current PK:" -NewLine $true
    $key = invoke-command -ScriptBlock $syncHash.Get_WindowsProductKey
    Show-Result -Font "Courier New" -Size "30" -Color "Cyan" -Text "{" -NewLine $false
    Show-Result -Font "Courier New" -Size "30" -Color "Yellow" -Text "$key" -NewLine $false
    Show-Result -Font "Courier New" -Size "30" -Color "Cyan" -Text "}" -NewLine $true
    Show-Result -Font "Courier New" -Size "30" -Color "LightGreen" -Text "            " -NewLine $true
    Show-Result -Font "Courier New" -Size "30" -Color "LightGreen" -Text "original PK:" -NewLine $true
    $key = wmic path softwarelicensingservice get OA3xOriginalProductKey | Out-String
    $key = $key.replace('OA3xOriginalProductKey','').trim()
    Show-Result -Font "Courier New" -Size "30" -Color "Cyan" -Text "{" -NewLine $false
    Show-Result -Font "Courier New" -Size "30" -Color "Yellow" -Text "$key" -NewLine $false
    Show-Result -Font "Courier New" -Size "30" -Color "Cyan" -Text "}" -NewLine $true
    Remove-Variable -Name "key"
})

$syncHash.GUI.SP.Add_Click({
    try{
        Start-Process -FilePath "sysdm.cpl" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0033]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.TM.Add_Click({
    try{
        Start-Process -FilePath "taskmgr.exe" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0034]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.REG.Add_Click({
    try{
        Start-Process -FilePath "regedit.exe" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0035]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.RemoteOpenedFiles.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0036]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    $a = (psfile.exe \\$cn /nobanner /accepteula)

    $a | ForEach-Object { Show-Result -Font "Courier New" -Size "18" -Color "LightGreen" -Text $_ -NewLine $true }
})

$syncHash.GUI.SI.Add_Click({
    try{
        Start-Process -FilePath "msinfo32.exe" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0037]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.FE.Add_Click({
    try{
        Start-Process -FilePath "explorer.exe" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0038]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.SF.Add_Click({
    try{
        Start-Process -FilePath "fsmgmt.msc" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0039]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.HF.Add_Click({
    try{
        Start-Process -FilePath "notepad.exe" -ArgumentList "C:\Windows\System32\drivers\etc\hosts" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0040]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.LU.Add_Click({
    try{
        Start-Process -FilePath "lusrmgr.msc" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0041]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.GP.Add_Click({
    try{
        Start-Process -FilePath "gpedit.msc" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0042]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.PH.Add_Click({
    try{
        Start-Process -FilePath "powershell.exe" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0043]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.CL.Add_Click({
    try{
        Start-Process -FilePath "cmd.exe" -ArgumentList "/t:0a" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0044]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.AD_Query.Add_Click({
    $cmd="$env:windir\system32\rundll32.exe"
    $param="dsquery.dll,OpenQueryWindow"
    try{
        Start-Process -FilePath $cmd -ArgumentList $param -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0045]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.RDP.Add_Click({
    try{
        Start-Process -FilePath "mstsc.exe" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0046]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.SCCM.Add_Click({
    $cn = $syncHash.Gui.cb_Target.Text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0047]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "The target is not alive." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }
    try{
        Start-Process -FilePath "C:\Microsoft Configuration Manager\AdminConsole\bin\i386\CmRcViewer.exe" -ArgumentList $cn -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0048]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.DSA.Add_Click({
    try{
        Start-Process -FilePath "dsa.msc" -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0049]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.GUI.BBC.Add_Click({
    Splash
})

$syncHash.GUI.WS.Add_Click({
    $syncHash.Gui.rtb_Output.Document.Blocks.Clear() # Clear output window

    $Image64 = "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"
    $Image = [System.Convert]::FromBase64String($Image64)
    [System.Windows.Forms.Clipboard]::SetImage($Image)
    
    Show-Result -Font "Courier New" -Size "10" -Color "Yellow" -Text "     " -NewLine $true
    Show-Result -Font "Courier New" -Size "10" -Color "Yellow" -Text "     " -NewLine $true

    $syncHash.Gui.RTB_Output.ScrollToEnd()
    $syncHash.Gui.RTB_Output.Paste()

    $text = "Copyright (C) 2001-2021 Mark Russinovich"
    Show-Result -Font "Times New Roman" -Size "20" -Color "LightGreen" -Text $text -NewLine $true
    $text = "Sysinternals - www.sysinternals.com"
    Show-Result -Font "Times New Roman" -Size "20" -Color "LightGreen" -Text $text -NewLine $true
    Show-Result -Font "Times New Roman" -Size "20" -Color "LightGreen" -Text " " -NewLine $true
    $text = "Some of the functionalities in this script depend on SysInternal tools."
    Show-Result -Font "Times New Roman" -Size "20" -Color "Yellow" -Text $text -NewLine $true
})

$syncHash.GUI.SE.Add_Click({
    $syncHash.Gui.rtb_Output.Document.Blocks.Clear() # Clear output window

    $text = "System-Explorer-for-Windows"
    Show-Result -Font "Times New Roman" -Size "40" -Color "Yellow" -Text $text -NewLine $true

    $text = "Copyright (C) Trevor Jones"
    Show-Result -Font "Times New Roman" -Size "20" -Color "LightGreen" -Text $text -NewLine $true
    Show-Result -Font "Times New Roman" -Size "20" -Color "LightGreen" -Text "   " -NewLine $true
    Show-Result -Font "Times New Roman" -Size "20" -Color "LightGreen" -Text "   " -NewLine $true
    $text = "System-Explorer - https://github.com/SMSAgentSoftware/System-Explorer-for-Windows"
    Show-Result -Font "Times New Roman" -Size "20" -Color "LightGreen" -Text $text -NewLine $true
    Show-Result -Font "Times New Roman" -Size "20" -Color "LightGreen" -Text " " -NewLine $true
    Show-Result -Font "Times New Roman" -Size "20" -Color "LightGreen" -Text " " -NewLine $true
    Show-Result -Font "Times New Roman" -Size "20" -Color "Yellow" -Text "Please download the latest script to the same folder of bbc.ps1." -NewLine $true
})

$syncHash.ISS_Scriptblock = {
    $url = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
    $output = "$env:TEMP\SysinternalsSuite.zip"

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","Downloading package ... ",$false

    try{
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $output
    } catch {
        $e = "[Error 0050]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","Failed",$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","Please see log for reasons.",$true
        $syncHash.control.ISS_scriptblock_completed = $true
        return
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Done",$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","Installing package ... ",$false
    Expand-Archive -Path "$env:TEMP\SysinternalsSuite.zip" -DestinationPath "C:\Sysinternals"
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Done",$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","Setting up environment ... ",$false
    $e=[System.Environment]::GetEnvironmentVariable('PATH','machine')+";C:\SysInternals"
    [System.Environment]::SetEnvironmentVariable('PATH', $e,[System.EnvironmentVariableTarget]::Machine)
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Done",$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","Removing temporary files ... ",$false
    Remove-Item -Path $output -Force
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Done",$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","Windows SysInternals Suite has been successfully installed.",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black","    ",$true

    $syncHash.control.ISS_scriptblock_completed = $true
}

$syncHash.GUI.ISS.Add_Click({
    # Disable wedgets
    $syncHash.Gui.ISS.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.ISS_Scriptblock)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GUI.PS.Add_Click({
    $Version      = "PSVersion = " + $PSVersionTable.PSVersion.Major + "." + $PSVersionTable.PSVersion.Minor + "." + $PSVersionTable.PSVersion.Build + "." + $PSVersionTable.PSVersion.Revision
    $Edition      = "PSEdition = " + $PSVersionTable.PSEdition
    
    Show-Result -Font "Times New Roman" -Size "20" -Color "LightGreen" -Text $Version -NewLine $true
    Show-Result -Font "Times New Roman" -Size "20" -Color "LightGreen" -Text $Edition -NewLine $true
})

$syncHash.GUI.RC.Add_Click({
    Show-Result -Font "Courier New" -Size "28" -Color "Cyan"       -Text "=========================" -NewLine $true
    Show-Result -Font "Courier New" -Size "28" -Color "Cyan"       -Text "Frequently Used Commands:" -NewLine $true
    Show-Result -Font "Courier New" -Size "28" -Color "Cyan"       -Text "=========================" -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "LightGreen" -Text "Services                  : " -NewLine $false
    Show-Result -Font "Courier New" -Size "20" -Color "Cyan"       -Text "cmd /c services.msc" -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "LightGreen" -Text "Registry Editor           : " -NewLine $false
    Show-Result -Font "Courier New" -Size "20" -Color "Cyan"       -Text "Regedit.exe" -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "LightGreen" -Text "Task Manager              : " -NewLine $false
    Show-Result -Font "Courier New" -Size "20" -Color "Cyan"       -Text "taskmgr.exe" -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "LightGreen" -Text "Control Panel             : " -NewLine $false
    Show-Result -Font "Courier New" -Size "20" -Color "Cyan"       -Text "Control.exe" -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "LightGreen" -Text "Device Manager            : " -NewLine $false
    Show-Result -Font "Courier New" -Size "20" -Color "Cyan"       -Text "cmd /c devmgmt.msc" -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "LightGreen" -Text "Computer Management       : " -NewLine $false
    Show-Result -Font "Courier New" -Size "20" -Color "Cyan"       -Text "cmd /c compmgmt.msc" -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "LightGreen" -Text "Local Groups and Users    : " -NewLine $false
    Show-Result -Font "Courier New" -Size "20" -Color "Cyan"       -Text "cmd /c lusrmgr.msc" -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "LightGreen" -Text "Local Group Policy Editor : " -NewLine $false
    Show-Result -Font "Courier New" -Size "20" -Color "Cyan"       -Text "cmd /c gpedit.msc" -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "LightGreen" -Text "Event Viewer              : " -NewLine $false
    Show-Result -Font "Courier New" -Size "20" -Color "Cyan"       -Text "cmd /c eventvwr.msc" -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "Yellow"     -Text "Session ID                : Local = 1; RDP = 2" -NewLine $true
})

$syncHash.GUI.NS.Add_Click({
    $copyright = [char]169

    $syncHash.Gui.rtb_Output.Document.Blocks.Clear() # Clear output window

    $Image64 = "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"
    $Image = [System.Convert]::FromBase64String($Image64)
    [System.Windows.Forms.Clipboard]::SetImage($Image)
    

    Show-Result -Font "Courier New" -Size "10" -Color "Yellow" -Text "     " -NewLine $true
    Show-Result -Font "Courier New" -Size "10" -Color "Yellow" -Text "     " -NewLine $true

    $syncHash.Gui.RTB_Output.ScrollToEnd()
    $syncHash.Gui.RTB_Output.Paste()

    Show-Result -Font "Courier New" -Size "20" -Color "Lime" -Text "$copyright David Wang, 2021 - V1.0" -NewLine $true
    Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "           " -NewLine $true
    Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "Required module: PSParallel" -NewLine $false
    Show-Result -Font "Courier New" -Size "18" -Color "LightGreen" -Text " (By Staffan Gustafsson)" -NewLine $false
    Show-Result -Font "Courier New" -Size "16" -Color "LightBlue" -Text " https://github.com/powercode/PSParallel" -NewLine $true
    Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "Required account type: " -NewLine $false
    Show-Result -Font "Courier New" -Size "18" -Color "Pink" -Text "Elevated domain admin" -NewLine $true
    Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "           " -NewLine $true
    Show-Result -Font "Courier New" -Size "18" -Color "Magenta" -Text "ESC" -NewLine $false
    Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text " to clear output window" -NewLine $false
    Show-Result -Font "Courier New" -Size "18" -Color "Chartreuse" -Text "  Auto-save sorted result to C:\PSScanner" -NewLine $true
})

$syncHash.GUI.LS.Add_Click({
    $syncHash.Gui.rtb_Output.Document.Blocks.Clear() # Clear output window

    Show-Result -Font "Courier New" -Size "20" -Color "Yellow" -Text "------------------------" -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "Lime" -Text "The MIT License (MIT)" -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "Cyan" -Text "Copyright (c) 2020, David Wang" -NewLine $true
    Show-Result -Font "Courier New" -Size "20" -Color "Yellow" -Text "------------------------" -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "Cyan" -Text "                 " -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "LightGreen" -Text 'Permission is hereby granted, free of charge, to any person obtaining a copy of this software and' -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "LightGreen" -Text 'associated documentation files (the "Software"), to deal in the Software without restriction,' -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "LightGreen" -Text 'including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,' -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "LightGreen" -Text 'and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,' -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "LightGreen" -Text 'subject to the following conditions:' -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "LightGreen" -Text '                 ' -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "LightGreen" -Text 'The above copyright notice and this permission notice shall be included in all copies or substantial' -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "LightGreen" -Text 'portions of the Software.' -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "LightGreen" -Text '                 ' -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "Yellow" -Text 'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT' -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "Yellow" -Text 'LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.' -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "Yellow" -Text 'IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,' -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "Yellow" -Text 'WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE' -NewLine $true
    Show-Result -Font "Courier New" -Size "16" -Color "Yellow" -Text 'SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.' -NewLine $true
})

$syncHash.check_scriptblock = {
    param (
        [string]$targ, # Target computer name
        [pscredential]$cred
    )

    [bool]$test
    [string]$tar = $targ.trim()

    # Ping test
    try {
        $test = [bool](Test-Connection -BufferSize 32 -Count 2 -ComputerName $Tar)
    } catch {
        $e = "[Error 0051]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
    if ($test) {
        $syncHash.ping_color = "Green"
        $syncHash.ping_text = $syncHash.emoji_check
        if($syncHash.timer_ping){
            $syncHash.timer_ping.Start() 2>$null
        }
    } else {
        $syncHash.ping_color = "Red"
        $syncHash.ping_text = $syncHash.emoji_error
        $syncHash.rdp_color = "Red"
        $syncHash.rdp_text = $syncHash.emoji_error
        $syncHash.permission_color = "Red"
        $syncHash.permission_text = $syncHash.emoji_error
        $syncHash.control.check_scriptblock_completed = $true
        return
    }

    # RDP connection test
    $test = (New-Object System.Net.Sockets.TCPClient -ArgumentList $Tar,3389 -ErrorAction Ignore).connected
    if ($test) {
        $syncHash.rdp_color = "Green"
        $syncHash.rdp_text = $syncHash.emoji_check
    } else {
        $syncHash.rdp_color = "Red"
        $syncHash.rdp_text = $syncHash.emoji_error
    }

    # Admin share permission test
    $path = "`\`\$tar`\admin$"

    if($cred){
        $test = Invoke-Command -ComputerName $targ -Credential $cred -ScriptBlock {
            $user = [Security.Principal.WindowsIdentity]::GetCurrent()
            $isAdmin = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

            $isAdmin
        }
    } else {
        $test = Test-Path $path
    }
    if ($test) {
        $syncHash.permission_color = "Green"
        $syncHash.permission_text = $syncHash.emoji_check
    } else {
        $syncHash.permission_color = "Red"
        $syncHash.permission_text = $syncHash.emoji_error
        $syncHash.control.check_scriptblock_completed = $true
        return
    }

    # Get uptime
    $up = (Get-Date) - [Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem -ComputerName $tar).LastBootUpTime)
    $syncHash.uptime_text = $up.Days.ToString().PadLeft(2,'0')+":"+$up.Hours.ToString().PadLeft(2,'0')+":"+$up.Minutes.ToString().PadLeft(2,'0')+":"+$up.Seconds.ToString().PadLeft(2,'0')+"."+$up.Milliseconds.ToString().PadLeft(3,'0')

    Remove-Variable -Name "tar" 2>$null
    Remove-Variable -Name "test" 2>$null
    Remove-Variable -Name "e" 2>$null
    Remove-Variable -Name "path" 2>$null
    Remove-Variable -Name "up" 2>$null

    $syncHash.control.check_scriptblock_completed = $true
}

$syncHash.GUI.btn_Check.Add_Click({
    # If the computer name field is blank, don't do anything
    if([string]::IsNullOrEmpty($syncHash.Gui.cb_Target.Text)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        Return
    }

    # Disable wedgets
    $syncHash.Gui.btn_Check.IsEnabled = $false
    $syncHash.Gui.Ping_Status.Content = ""
    $syncHash.Gui.RDP_enabled.Content = ""
    $syncHash.Gui.Permission.Content = ""
    $syncHash.Gui.Uptime.Content = ""
    $syncHash.Ping_Status = $false
    $syncHash.RDP_enabled = $false
    $syncHash.permission = $false
    $syncHash.uptime_text = ""

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.check_scriptblock).AddArgument($syncHash.Gui.cb_Target.Text).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

################################################# AD Tab #####################################################
# AD User search
$syncHash.GUI.btn_UserSearch.Add_Click({
    # If the username field is blank, don't do anything
    if([string]::IsNullOrEmpty($syncHash.Gui.tb_usersname.Text)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No name provided." -NewLine $true
        Return
    }

    [string]$sn = $syncHash.Gui.tb_usersname.Text
    $EmailRegex = '^([\w-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$'

    if ($sn -match $EmailRegex) {
        $a = Get-ADUser -Filter "UserPrincipalName -Like '$sn'" | Out-String
        if($a){
            $a = $a -replace "`n",""
            Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text $a -NewLine $true
        }else {
            Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "Nothing found." -NewLine $true
        }

        return
    }

    if(($sn.Split(' ').Count) -gt 1){
        $a = Get-ADUser -Filter "Name -Like '$sn'" | Out-String
        if($a){
            $a = $a -replace "`n",""
            Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text $a -NewLine $true
        }else {
            Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "Nothing found." -NewLine $true
        }
    } else {
        $a = Get-ADUser -Filter "SamAccountName -Like '$sn'" | Out-String
        if($a){
            $a = $a -replace "`n",""
            Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text $a -NewLine $true
        }else {
            Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "Nothing found." -NewLine $true
        }
    }
})

# Reset AD User password (SAM)
$syncHash.GUI.btn_pwReset.Add_Click({
    # If the username field is blank, don't do anything
    if([string]::IsNullOrEmpty($syncHash.Gui.tb_usersname.Text)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No name provided." -NewLine $true
        Return
    }

    [string]$sn = $syncHash.Gui.tb_usersname.Text

    if(($sn.Split(' ').Count) -gt 1){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text " Invalid SAM account name." -NewLine $true
        Return
    }

    $credential = Get-Credential -UserName $sn -Message "Please input your new password:"
    Set-ADAccountPassword $sn -Reset -NewPassword $credential.Password -PassThru
})

function Test-ADCredential {
    [CmdletBinding()]
    param(
        [pscredential]$Cre
    )
     
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement

        if($Cre.username.split("\").count -ne 2) {
            $e = "[Error 0052] You haven't entered credentials in DOMAIN\USERNAME format. Given value : $($Cre.Username)"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        }
     
        $DomainName = $Cre.username.Split("\")[0]
        $UserName = $Cre.username.Split("\")[1]
        $Password = $Cre.GetNetworkCredential().Password
     
        $PC = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $DomainName)
        if($PC.ValidateCredentials($UserName,$Password)) {
            $e = "[Error 0053] Credential validation successful for $($Cre.Username)"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            return $true
        } else {
            $e = "[Error 0054] Credential validation failed for $($Cre.Username)"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            return $false
        }
    } catch {
        $e = "[Error 0055] Error occurred while performing credential validation $_"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        return $false
    }
}

# Test AD User password (SAM)
$syncHash.GUI.btn_pwTest.Add_Click({
    # If the username field is blank, don't do anything
    if([string]::IsNullOrEmpty($syncHash.Gui.tb_usersname.Text)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No account ID provided." -NewLine $true
        Return
    }

    [string]$sn = $syncHash.Gui.tb_usersname.Text

    if(($sn.Split(' ').Count) -gt 1){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text " Invalid SAM account name." -NewLine $true
        Return
    }
    $credential = Get-Credential -UserName $sn -Message "Please input your password:"

    if(!$credential){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "Request cancelled." -NewLine $true
        return
    }

    if($credential.username.split("\").count -ne 2) {
        $e = "Credential not in DOMAIN\USERNAME format."
        Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text $e -NewLine $true
        return
    }

    [bool]$s = Test-ADCredential -Cre $credential

    if($s){
        Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text "Success" -NewLine $true
    } else {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "Failed" -NewLine $true
    }
})

# Unlock AD user account
$syncHash.GUI.btn_Unlock.Add_Click({
    if([string]::IsNullOrEmpty($syncHash.Gui.tb_usersname.Text)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No account ID provided." -NewLine $true
        Return
    }

    [string]$sn = $syncHash.Gui.tb_usersname.Text

    if(($sn.Split(' ').Count) -gt 1){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "Invalid SAM account name" -NewLine $true
        Return
    }

    try {
        Unlock-ADAccount -Identity $sn
        Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text "Success" -NewLine $true
    } catch {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "Failed" -NewLine $true
    }
})

$syncHash.user_detail_scriptblock = {
    param (
        [string]$sn # User AD account ID
    )

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","===== User $sn detail =====",$true

    try{
        $a = Get-ADUser $sn -Properties * 2>$null | Out-String
    } catch {
        
    }
    if($a){
        $a = $a -replace "`n",""
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$a,$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","User not found.",$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","===== User $sn group membership =====",$true

    try{
        $a = Get-ADPrincipalGroupMembership $sn | Select-Object name | out-string
    } catch {
        
    }
    if($a){
        $a = $a -replace "`n",""
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$a,$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","User not found.",$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","===== End =====",$true

    $syncHash.control.user_detail_scriptblock_completed = $true
}

# User detail
$syncHash.GUI.btn_Detail.Add_Click({
    if([string]::IsNullOrEmpty($syncHash.Gui.tb_usersname.Text)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No account ID provided." -NewLine $true
        Return
    }

    [string]$sn = $syncHash.Gui.tb_usersname.Text

    if(($sn.Split(' ').Count) -gt 1){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "Invalid SAM account name" -NewLine $true
        Return
    }

    # Disable wedgets
    $syncHash.Gui.btn_UserSearch.IsEnabled = $false
    $syncHash.Gui.btn_pwReset.IsEnabled    = $false
    $syncHash.Gui.btn_pwTest.IsEnabled     = $false
    $syncHash.Gui.btn_Unlock.IsEnabled     = $false
    $syncHash.Gui.btn_Detail.IsEnabled     = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.user_detail_scriptblock).AddArgument($sn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Delete a Computer
$syncHash.GUI.btn_cDelete.Add_Click({
    if([string]::IsNullOrEmpty($syncHash.Gui.tb_cname.Text)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No computer name provided." -NewLine $true
        Return
    }

    [string]$cn = $syncHash.Gui.tb_cname.Text

    if(($cn.Split(' ').Count) -gt 1){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "Invalid computer name" -NewLine $true
        Return
    }

    try {
        Remove-ADComputer -Identity $cn
        Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text "Success" -NewLine $true
    } catch {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "Failed" -NewLine $true
    }
})

# Computer detail
$syncHash.GUI.btn_cDetail.Add_Click({
    if([string]::IsNullOrEmpty($syncHash.Gui.tb_cname.Text)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No computer name provided." -NewLine $true
        Return
    }

    [string]$cn = $syncHash.Gui.tb_cname.Text

    if(($cn.Split(' ').Count) -gt 1){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "Invalid computer name" -NewLine $true
        Return
    }

    try{
        $a = Get-ADComputer $cn -Properties * | Out-String
        $a = $a -replace "`n",""
        Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text $a -NewLine $true
    } catch {
        Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "Computer not found." -NewLine $true
    }
})

# Restore deleted computer
$syncHash.GUI.btn_cRestore.Add_Click({
    if([string]::IsNullOrEmpty($syncHash.Gui.tb_cname.Text)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No computer name provided." -NewLine $true
        Return
    }

    [string]$cn = $syncHash.Gui.tb_cname.Text

    if(($cn.Split(' ').Count) -gt 1){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "Invalid computer name" -NewLine $true
        Return
    }

    Get-ADObject -Filter {displayName -eq $cn} -IncludeDeletedObjects | Restore-ADObject
    $a = Get-ADComputer $cn | Out-String
    $a = $a -replace "`n",""
    Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text $a -NewLine $true
})

$syncHash.getBitLockerRecoveryKey_scriptblock = {
    Param(
        [String]$Key,
        [Bool]$ID
    )

    Function Get-BitLockerRecovery {
        [CmdletBinding(DefaultParameterSetName="Name")]
        param(
            [parameter(ParameterSetName="Name",Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
                [alias("ComputerName")]
                [String[]] $Name,
            [parameter(ParameterSetName="PdID",Mandatory=$true)]
            [String] $PdID, # PdID has to be validated from the caller
            [String] $Domain,
            [String] $Server,
            [Management.Automation.PSCredential] $Credential
        )
    
        begin {
            # Pathname object contstants
            $ADS_SETTYPE_DN = 4
            $ADS_FORMAT_X500_PARENT = 8
            $ADS_DISPLAY_VALUE_ONLY = 2
    
            # Pathname object used by Get-ParentPath function
            $Pathname = New-Object -ComObject "Pathname"
    
            # Returns the parent path of a distinguished name
            function Get-ParentPath {
                param(
                [String] $distinguishedName
                )
                [Void] $Pathname.GetType().InvokeMember("Set", "InvokeMethod", $null, $Pathname, ($distinguishedName, $ADS_SETTYPE_DN))
                $Pathname.GetType().InvokeMember("Retrieve", "InvokeMethod", $null, $Pathname, $ADS_FORMAT_X500_PARENT)
            }
    
            # Returns only the name of the first element of a distinguished name
            function Get-NameElement {
                param(
                [String] $distinguishedName
                )
                [Void] $Pathname.GetType().InvokeMember("Set", "InvokeMethod", $null, $Pathname, ($distinguishedName, $ADS_SETTYPE_DN))
                [Void] $Pathname.GetType().InvokeMember("SetDisplayType", "InvokeMethod", $null, $Pathname, $ADS_DISPLAY_VALUE_ONLY)
                $Pathname.GetType().InvokeMember("GetElement", "InvokeMethod", $null, $Pathname, 0)
            }
    
            # Outputs a custom object based on a list of hash tables
            function Out-Object {
                param(
                [System.Collections.Hashtable[]] $hashData
                )
                $order = @()
                $result = @{}
                $hashData | ForEach-Object {
                $order += ($_.Keys -as [Array])[0]
                $result += $_
                }
                New-Object PSObject -Property $result | Select-Object $order
            }
    
            # Create and initialize DirectorySearcher object that finds computers
            $ComputerSearcher = [ADSISearcher] ""
    
            function Initialize-ComputerSearcher {
                if ( $Domain ) {
                    if ( $Server ) {
                        $path = "LDAP://$Server/$Domain"
                    }
                    else {
                        $path = "LDAP://$Domain"
                    }
                }
                else {
                    if ( $Server ) {
                        $path = "LDAP://$Server"
                    }
                    else {
                        $path = ""
                    }
                }
    
                if ( $Credential ) {
                    $networkCredential = $Credential.GetNetworkCredential()
                    $dirEntry = New-Object DirectoryServices.DirectoryEntry($path,$networkCredential.UserName,$networkCredential.Password)
                }
                else {
                    $dirEntry = [ADSI] $path
                }
    
                $ComputerSearcher.SearchRoot = $dirEntry
                $ComputerSearcher.Filter = "(objectClass=domain)"
    
                try {
                    [Void] $ComputerSearcher.FindOne()
                }
                catch [Management.Automation.MethodInvocationException] {
                    throw $_.Exception.InnerException
                }
            }
            Initialize-ComputerSearcher
    
            # Create and initialize DirectorySearcher for finding msFVE-RecoveryInformation objects
            $RecoverySearcher = [ADSISearcher] ""
            $RecoverySearcher.PageSize = 100
            $RecoverySearcher.PropertiesToLoad.AddRange(@("distinguishedName","msFVE-RecoveryGuid","msFVE-RecoveryPassword","name"))
    
            # Gets the DirectoryEntry object for a specified computer
            function Get-ComputerDirectoryEntry {
                param(
                    [String] $name
                )
                $ComputerSearcher.Filter = "(&(objectClass=computer)(name=$name))"
                try {
                    $searchResult = $ComputerSearcher.FindOne()
                    if ( $searchResult ) {
                        $searchResult.GetDirectoryEntry()
                    }
                } catch [Management.Automation.MethodInvocationException] {
                    Write-Error -Exception $_.Exception.InnerException
                }
            }
    
            # Outputs $true if the piped DirectoryEntry has the specified property set, or $false otherwise
            function Test-DirectoryEntryProperty {
                param(
                    [String] $property
                )
                process {
                    try {
                        $null -ne $_.Get($property)
                    } catch [Management.Automation.MethodInvocationException] {
                        $false
                    }
                }
            }
    
            # Gets a property from a ResultPropertyCollection; specify $propertyName in lowercase to remain compatible with PowerShell v2
            function Get-SearchResultProperty {
                param(
                    [DirectoryServices.ResultPropertyCollection] $properties,
                    [String] $propertyName
                )
                if ( $properties[$propertyName] ) {
                    $properties[$propertyName][0]
                }
            }
    
            # Gets BitLocker recovery information for the specified computer
            function GetBitLockerRecovery {
                param(
                    $name
                )
                $domainName = $ComputerSearcher.SearchRoot.dc
                $computerDirEntry = Get-ComputerDirectoryEntry $name
                if ( -not $computerDirEntry ) {
                    Write-Error "Unable to find computer '$name' in domain '$domainName'" -Category ObjectNotFound
                    return
                }
                # If the msTPM-OwnerInformation (Vista/Server 2008/7/Server 2008 R2) or
                # msTPM-TpmInformationForComputer (Windows 8/Server 2012 or later)
                # attribute is set, then TPM recovery information is stored in AD
                $tpmRecoveryInformation = $computerDirEntry | Test-DirectoryEntryProperty "msTPM-OwnerInformation"
                if ( -not $tpmRecoveryInformation ) {
                    $tpmRecoveryInformation = $computerDirEntry | Test-DirectoryEntryProperty "msTPM-TpmInformationForComputer"
                }
                $RecoverySearcher.SearchRoot = $computerDirEntry
                $searchResults = $RecoverySearcher.FindAll()
                foreach ( $searchResult in $searchResults ) {
                    $properties = $searchResult.Properties
                    $recoveryPassword = Get-SearchResultProperty $properties "msfve-recoverypassword"
                    if ( $recoveryPassword ) {
                        $recoveryDate = ([DateTimeOffset] ((Get-SearchResultProperty $properties "name") -split '{')[0]).DateTime
                        $passwordID = ([Guid] [Byte[]] (Get-SearchResultProperty $properties "msfve-recoveryguid")).Guid
                    }
                    else {
                        $tpmRecoveryInformation = $recoveryDate = $passwordID = $recoveryPassword = "N/A"
                    }
                    Out-Object `
                        @{"distinguishedName"      = $computerDirEntry.Properties["distinguishedname"][0]},
                        @{"name"                   = $computerDirEntry.Properties["name"][0]},
                        @{"TPMRecoveryInformation" = $tpmRecoveryInformation},
                        @{"Date"                   = $recoveryDate},
                        @{"PasswordID"             = $passwordID.ToUpper()},
                        @{"RecoveryPassword"       = $recoveryPassword.ToUpper()}
                }
                $searchResults.Dispose()
            }
    
            # Searches for BitLocker recovery information for the specified password ID
            function SearchBitLockerRecoveryByPasswordID {
                param(
                    [String]$pwdID
                )
                $RecoverySearcher.Filter = "(&(objectClass=msFVE-RecoveryInformation)(name=*{$pwdID-*}))"
                $searchResults = $RecoverySearcher.FindAll()
                foreach ( $searchResult in $searchResults ) {
                    $properties = $searchResult.Properties
                    $computerName = Get-NameElement (Get-ParentPath (Get-SearchResultProperty $properties "distinguishedname"))
                    $RecoverySearcher.Filter = "(objectClass=msFVE-RecoveryInformation)"
                    GetBitLockerRecovery $computerName | Where-Object { $_.PasswordID -match "^$pwdID-" }
                }
                $searchResults.Dispose()
            }
        }
    
        process {
            if ( $PSCmdlet.ParameterSetName -eq "Name" ) {
                $RecoverySearcher.Filter = "(objectClass=msFVE-RecoveryInformation)"
                foreach ( $nameItem in $Name ) {
                    GetBitLockerRecovery $nameItem
                }
            } elseif ( $PSCmdlet.ParameterSetName -eq "PdID" ) {
                SearchBitLockerRecoveryByPasswordID $PdID
            }
        }
    }

    if($ID){
        $a = Get-BitLockerRecovery -PdID $Key | Out-String
    } else {
        $a = Get-BitLockerRecovery -ComputerName $Key | Out-String
    }

    if($a) {
        $a = $a -replace "`n",""
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Lime",$a,$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow","Key not found",$true
    }

    $syncHash.control.getBitLockerRecoveryKey_scriptblock_Completed = $true
}

$syncHash.GUI.btn_rGet.Add_Click({
    if([string]::IsNullOrEmpty($syncHash.Gui.tb_keyID.Text)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No computer name provided." -NewLine $true
        Return
    }

    [string]$id = $syncHash.Gui.tb_keyID.Text
    [bool]$useID = $true

    if($syncHash.Gui.rb_KeyID.IsChecked){
        # if($id.length -eq 8){ # Validate the Key ID
        if($id -match '^[0-9A-F]{8}$') {
            $useID = $true
        } else {
            Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "$Global:emoji_angry Key ID needs to be exactly 8 characters, and only numbers and letters can be used." -NewLine $true
            return
        }
    } else {
        $useID = $false
    }

    # Disable wedgets
    $syncHash.Gui.btn_rGet.IsEnabled = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.getBitLockerRecoveryKey_scriptblock).AddArgument($id).AddArgument($useID)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

###################################################################################################################################
$syncHash.GUI.btn_Load.Add_Click({
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $filename = New-Object System.Windows.Forms.OpenFileDialog
    $filename.initialDirectory = $PSScriptRoot
    $filename.Filter = "Text files(*.txt)|*.txt|All files (*.*)|*.*"
    $file = @()
    if($filename.ShowDialog() -eq "OK") {
        $file += $filename.FileName
    } else {
        return
    }
    $users = Get-Content -Path $file
    $syncHash.Gui.lb_UserList.items.Clear()
    foreach($user in $users) {
        if(!($syncHash.Gui.lb_UserList.items.Contains($user))){
            $syncHash.Gui.lb_UserList.items.add($user)
        }
    }
})

$syncHash.GUI.rb_Target.Add_Click({
    $syncHash.GUI.lb_tList.Items.Clear()
})

$syncHash.GUI.rb_File.Add_Click({
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $filename = New-Object System.Windows.Forms.OpenFileDialog
    $filename.initialDirectory = $PSScriptRoot
    $filename.Filter = "Text files(*.txt)|*.txt|All files (*.*)|*.*"
    $file = @()
    if($filename.ShowDialog() -eq "OK") {
        $file += $filename.FileName
    } else {
        $syncHash.GUI.rb_Target.IsChecked = $true
        return
    }
    $users = Get-Content -Path $file
    $syncHash.Gui.lb_tList.items.Clear()
    foreach($user in $users) {
        if(!($syncHash.Gui.lb_tList.items.Contains($user))){
            $syncHash.Gui.lb_tList.items.add($user)
        }
        
    }
})

$syncHash.grant_scriptblock = {
    param(
		[System.Collections.ArrayList]$C,
		[System.Collections.ArrayList]$U
	)

    function Find-User-Account {
        param(
            [string]$SA
        )

        try
        {
            $ADResolve = ([adsisearcher]"(samaccountname=$SA)").findone().properties['samaccountname']
        }
        catch
        {
            $ADResolve = $null
        }
        $ADResolve
    }

    function Grant {
        param(
            [string]$U,
            [string]$C
        )
    
        $ADResolved
    
        if ($U -notmatch '\\') {
            $ADResolved = Find-User-Account -SA $U
            $U = 'WinNT://',"$env:userdomain",'/',$ADResolved -join ''
        } else {
            $ADResolved = ($U -split '\\')[1]
            $DomainResolved = ($U -split '\\')[0]
            $U = 'WinNT://',$DomainResolved,'/',$ADResolved -join ''
        }

        $msg = "Adding `'$ADResolved`' to Admin group on `'$C`'         "
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$false
    
        try {
            ([ADSI]"WinNT://$C/Administrators,group").add($U)
            $msg = "Success"
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Cyan",$msg,$true
        } catch {
            $msg = "Failed"
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true

            $e = "[Error 0056] Error adding $U to the local admin group on $C."
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        }
        Remove-Variable -Name "ADResolved" 2>$null
        Remove-Variable -Name "DomainResolved" 2>$null
        Remove-Variable -Name "msg" 2>$null
        Remove-Variable -Name "e" 2>$null
    }

    $C | ForEach-Object {
        $cc = $_
        $U | ForEach-Object {
            Grant -U $_ -C $cc
        }
    }
    $msg = "Done"
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Cyan",$msg,$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "cc" 2>$null
    Remove-Variable -Name "msg" 2>$null

    $syncHash.control.grant_scriptblock_completed = $true
}

$syncHash.remove_scriptblock = {
    param(
		[System.Collections.ArrayList]$C,
		[System.Collections.ArrayList]$U
	)

    function Find-User-Account {
        param(
            [string]$SA
        )

        try
        {
            $ADResolve = ([adsisearcher]"(samaccountname=$SA)").findone().properties['samaccountname']
        }
        catch
        {
            $ADResolve = $null
        }
        $ADResolve
    }

    function Remove {
        param(
            [string]$U,
            [string]$C
        )
    
        $ADResolved
        $msg

        if ($U -notmatch '\\') {
            $ADResolved = Find-User-Account -SA $U
            $U = 'WinNT://',"$env:userdomain",'/',$ADResolved -join ''
        } else {
            $ADResolved = ($U -split '\\')[1]
            $DomainResolved = ($U -split '\\')[0]
            $U = 'WinNT://',$DomainResolved,'/',$ADResolved -join ''
        }

        $msg = "Removing `'$ADResolved`' from Admin group on `'$C`'         "
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$False

        [bool]$s = $False

        try {
            ([ADSI]"WinNT://$C/Administrators,group").remove($U) 2>&1 | Out-Null
            $msg = "Success"
            $s = $true
        } catch {
            $msg = "Failed"
            $s = $False
        }

        if($s){
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Cyan",$msg,$true
        }else{
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true
            $e = "[Error 0057] Error removing $U from the local admin group on $C."
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        }
        Remove-Variable -Name "ADResolved" 2>$null
        Remove-Variable -Name "msg" 2>$null
        Remove-Variable -Name "DomainResolved" 2>$null
        Remove-Variable -Name "s" 2>$null
        Remove-Variable -Name "e" 2>$null
    }

    $C | ForEach-Object {
        $cc = $_
        $U | ForEach-Object {
            Remove -U $_ -C $cc
        }
    }
    $msg = "Done"
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Cyan",$msg,$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true
    Remove-Variable -Name "msg" 2>$null
    Remove-Variable -Name "cc" 2>$null
    $syncHash.control.grant_scriptblock_completed = $true
}

$syncHash.GUI.btn_Grant.Add_Click({
    $cn = [System.Collections.ArrayList]@()
    $us = [System.Collections.ArrayList]@()

    # Check how to get target
    if($syncHash.Gui.rb_Target.IsChecked) {
        # If the computer name field is blank, don't do anything
        if([string]::IsNullOrEmpty($syncHash.Gui.cb_Target.Text)) {
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
            Return
        } else {
            $cn.add($syncHash.Gui.cb_Target.Text)
            if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
                $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
            }
        }
    }

    if($syncHash.Gui.rb_File.IsChecked) {
        if($syncHash.Gui.lb_tList.items.count -eq 0) {
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No target listed." -NewLine $true
            return
        }
        $syncHash.Gui.lb_tList.items | ForEach-Object {
            if([string]::IsNullOrEmpty($_)) {
                
            } else {
                $cn.add($_)
            }
        }
    }

    if($syncHash.Gui.lb_UserList.Items.Count -eq 0) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No user listed." -NewLine $true
        return
    } else {
        $syncHash.Gui.lb_UserList.Items | ForEach-Object {
            if([string]::IsNullOrEmpty($_)) {
                
            } else {
                $us.add($_)
            }
        }
    }

    # Disable wedgets
    $syncHash.Gui.btn_Load.IsEnabled   = $False
    $syncHash.Gui.btn_clr.IsEnabled    = $False
    $syncHash.Gui.btn_Add.IsEnabled    = $False
    $syncHash.Gui.btn_Grant.IsEnabled  = $False
    $syncHash.Gui.btn_Remove.IsEnabled = $False
    $syncHash.Gui.btn_List.IsEnabled   = $False
    $syncHash.Gui.btn_Reset.IsEnabled  = $False
    $syncHash.Gui.btn_Test.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.grant_scriptblock).AddArgument($cn).AddArgument($us)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GUI.btn_Remove.Add_Click({
    $cn = [System.Collections.ArrayList]@()
    $us = [System.Collections.ArrayList]@()

    # Check how to get target
    if($syncHash.Gui.rb_Target.IsChecked) {
        # If the computer name field is blank, don't do anything
        if([string]::IsNullOrEmpty($syncHash.Gui.cb_Target.Text)) {
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
            Return
        } else {
            $cn.add($syncHash.Gui.cb_Target.Text)
            if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
                $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
            }
        }
    }

    if($syncHash.Gui.rb_File.IsChecked) {
        if($syncHash.Gui.lb_tList.items.count -eq 0) {
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No target listed." -NewLine $true
            return
        }
        $syncHash.Gui.lb_tList.items | ForEach-Object {
            if([string]::IsNullOrEmpty($_)) {
                
            } else {
                $cn.add($_)
            }
        }
    }

    if($syncHash.Gui.lb_UserList.Items.Count -eq 0) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No user listed." -NewLine $true
        return
    } else {
        $syncHash.Gui.lb_UserList.Items | ForEach-Object {
            if([string]::IsNullOrEmpty($_)) {
                
            } else {
                $us.add($_)
            }
        }
    }

    # Disable wedgets
    $syncHash.Gui.btn_Load.IsEnabled   = $False
    $syncHash.Gui.btn_clr.IsEnabled    = $False
    $syncHash.Gui.btn_Add.IsEnabled    = $False
    $syncHash.Gui.btn_Grant.IsEnabled  = $False
    $syncHash.Gui.btn_Remove.IsEnabled = $False
    $syncHash.Gui.btn_List.IsEnabled   = $False
    $syncHash.Gui.btn_Reset.IsEnabled  = $False
    $syncHash.Gui.btn_Test.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.remove_scriptblock).AddArgument($cn).AddArgument($us)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.sList_scriptblock = {
    param(
		[string]$cn,
        [pscredential]$cred
    )
    
    try {
        if($cred){
            $result = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock {
                $r = Get-CimInstance -ClassName win32_product
                $r
            }
            $result | Out-GridView -Title "Application list on $cn"
        } else {
            $result = Invoke-Command -ComputerName $cn -ScriptBlock {
                $r = Get-CimInstance -ClassName win32_product
                $r
            }
            $result | Out-GridView -Title "Application list on $cn"
        }
    } catch {
        $e = "[Error 0058] Error retreiving service list from $cn."
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        Remove-Variable -Name "e"
    }

    $syncHash.control.sList_scriptblock_completed = $true
}

$syncHash.GUI.btn_SoftwareList.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.Text
    # If the computer name field is blank, don't do anything
    if([string]::IsNullOrEmpty($cn)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        Return
    }

    # Disable wedgets
    $syncHash.GUI.btn_SoftwareList.IsEnabled = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.sList_scriptblock).AddArgument($cn).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Worker thread for scanning subnet
$syncHash.scan_scriptblock = {
    param(
        [string]$start,
        [string]$end,
        [int]$threshold,
        [bool]$more,
        [bool]$arp
    )

    [int]$DelayMS = 2
    [bool]$ARP_Clear = $true

    $StartArray = $start.Split('.')
    $EndArray = $end.Split('.')

    [int]$Oct3First = $StartArray[2] -as [int]
    [int]$Oct3Last  = $EndArray[2]   -as [int]
    [int]$Oct4First = $StartArray[3] -as [int]
    [int]$Oct4Last  = $EndArray[3]   -as [int]

    if($StartArray[0] -ne $EndArray[0]){
        $msg = "IP range too large to handle, CIDR >= 16"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow",$msg,$true

        $syncHash.control.scan_scriptblock_completed = $true

        return
    }

    if($StartArray[1] -ne $EndArray[1]){
        $msg = "IP range too large to handle, CIDR should be larger than 16"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow",$msg,$true

        $syncHash.control.scan_scriptblock_completed = $true

        return
    }

    $Time = [System.Diagnostics.Stopwatch]::StartNew()

    $syncHash.mutex.WaitOne()
    $syncHash.Count = 0
    $syncHash.mutex.ReleaseMutex()
    
    # Calculate IP address set based on IP range
    # In case of 16 <= CIDR < 24
    if($StartArray[2] -ne $EndArray[2]){
        if($Oct4First -eq 0){
            $Oct4First++
        }

        if($Oct4Last -eq 255){
            $Oct4Last--
        }

        $IPAddresses = $Oct3First..$Oct3Last | ForEach-Object {
            $t = $_
            $Oct4First..$Oct4Last | ForEach-Object {
                $StartArray[0]+'.'+$StartArray[1]+'.'+$t+'.'+$_
            }
        }
    } elseif(($StartArray[2] -eq $EndArray[2]) -and ($StartArray[3] -ne $EndArray[3])){ # In case of CIDR >= 24
        if($Oct4First -eq 0){
            $Oct4First++
        }

        if($Oct4Last -eq 255){
            $Oct4Last--
        }

        $IPAddresses = $Oct4First..$Oct4Last | ForEach-Object {$StartArray[0]+'.'+$StartArray[1]+'.'+$StartArray[2]+'.'+$_}
    }

    $msg = "IP"
    $msg = $msg.PadRight(17,' ') + "Hostname"

    if($more){
        $msg = $msg.PadRight(49,' ') + "Logon-User"
        $msg = $msg.PadRight(69,' ') + "SerialNumber"
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow",$msg,$true

    if($arp){
        if($ARP_Clear) {
            arp -d # Clear ARP cache
        }

        $ArpScriptBlock = { # Thread to send out UDP requests. When the IP is not in local arp cache, Windows will send arp request broadcast, then the local arp cache is built
            $ASCIIEncoding = New-Object System.Text.ASCIIEncoding
            $Bytes = $ASCIIEncoding.GetBytes("a")
            $UDP = New-Object System.Net.Sockets.Udpclient

            $UDP.Connect($_,1)
            [void]$UDP.Send($Bytes,$Bytes.length)

            if ($DelayMS) {
                [System.Threading.Thread]::Sleep($DelayMS) # set to 0 when your network is fast, other wise set it higher ( 0 - 9 ms)
            }
        }
        $IPAddresses | Invoke-Parallel -ThrottleLimit $threshold -ProgressActivity "UDP Pinging Progress" -ScriptBlock $ArpScriptBlock

        $Hosts = arp -a # Dos command for listing local arp cache

        $Hosts = $Hosts | Where-Object {$_ -match "dynamic"} | ForEach-Object {($_.trim() -replace " {1,}",",") | ConvertFrom-Csv -Header "IP","MACAddress"}
        $Hosts = $Hosts | Where-Object {$_.IP -in $IPAddresses}
    }

    if($arp){
        $ips = $Hosts # for arp scan, we only query the live nodes
    } else {
        $ips = $IPAddresses # for ICMP scan, we test all IPs
    }

    $ips | Invoke-Parallel -ThrottleLimit $threshold -ProgressActivity "Scanning Progress" -ScriptBlock { # test/query worker thread
        [bool]$test  = $false
        [string]$msg = ""
        [string]$cn  = ""
        [string]$ip  = ""
        
        if($arp){
            $test = $true
            $ip = $_.IP
        } else {
            $ip = $_
            $test = [bool](Test-Connection -BufferSize 32 -Count 3 -ComputerName $ip -ErrorAction SilentlyContinue)
        }

        if($test){ # for arp, all nodes are alive. for ICMP, Test-Connection return value will tell you if it is alive
            $syncHash.mutex.WaitOne()
            $syncHash.Count = $syncHash.Count + 1
            $syncHash.mutex.ReleaseMutex()

            $hsEntry = [System.Net.Dns]::GetHostEntry($ip)  # reverse DNS lookup
                
            if($hsEntry){
                if($more){
                    $cn = (($hsEntry.HostName).Split('.'))[0]
                } else {
                    $cn = $hsEntry.HostName
                }
            } else {
                $cn = "..."
            }
                
            $msg = $ip.PadRight(17,' ') + $cn

            Remove-Variable -Name 'ip'

            if($more){
                $a = query user /server:$cn # Query current logon user
                if($a){
                    $b = ((($a[1]) -replace '^>', '') -replace '\s{2,}', ',').Trim() | ForEach-Object {
                        if ($_.Split(',').Count -eq 5) {
                            Write-Output ($_ -replace '(^[^,]+)', '$1,')
                        } else {
                            Write-Output $_
                        }
                    }
                    $c = ($b.split(','))[0]
                } else {
                    $c = "..."
                }
                $msg = $msg.PadRight(49,' ') + $c
                
                # WMI remote query serial number, works only when RPC is running on the target
                $sn = (Get-WmiObject -ComputerName $cn -class win32_bios).SerialNumber
                if($sn){
                    $msg = $msg.PadRight(69,' ') + $sn                    } 
                else {
                    $msg = $msg.PadRight(69,' ') + "..."
                }
            }
            # we need to limit local function call as less as possible
            $objHash = @{
                font    = "Courier New"
                size    = "20"
                color   = "MediumSpringGreen"
                msg     = $msg
                newline = $true
            }
            $syncHash.Q.Enqueue($objHash)
            Remove-Variable -Name "objHash"
        }
    }

    # total alive nodes
    if($arp){
        $total = $Hosts.Count
    } else {
        $total = ($Oct4Last - $Oct4First + 1) * ($Oct3Last - $Oct3First + 1)
    }

    $msg = "Total "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","White","     ",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","White",$msg,$false

    $msg = $total.ToString()
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Orange",$msg,$false

    $msg = " IP(s) scanned in ["
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","White",$msg,$false

    $currenttime = $Time.Elapsed

    $d = ($currenttime.days).ToString()
    $h = ($currenttime.hours).ToString()
    $m = ($currenttime.minutes).ToString()
    $s = ($currenttime.seconds).ToString()
    $t = ($currenttime.Milliseconds).ToString()
    $msg = $d + ":" + $h + ":" + $m + ":" + $s + ":" + $t
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Orange",$msg,$false

    $msg = "],  Total "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","White",$msg,$false

    $syncHash.mutex.WaitOne()
    $msg = ($syncHash.Count).ToString()
    $syncHash.mutex.ReleaseMutex()
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Magenta",$msg,$false

    $msg = " node(s) alive."
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","White",$msg,$true

    $msg = "===== Scanning network " + $start +" --- " + $end + " completed ====="
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","YellowGreen",$msg,$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true
    
    $syncHash.mutex.WaitOne()
    $syncHash.Count = 0
    $syncHash.mutex.ReleaseMutex()

    $Time.Stop()
    Remove-Variable -Name "Time"

    $syncHash.control.scan_scriptblock_completed = $true
}

# Handle Scan Button click event
$syncHash.GUI.btn_Scan.Add_Click({
    [int]$threshold = 50
    if([string]::IsNullOrEmpty($syncHash.Gui.NS_Threshold.text)){
        $syncHash.Gui.NS_Threshold.text = "50"
        $threshold = 50
    } else {
        $threshold = ($syncHash.GUI.NS_Threshold.text) -as [int]
    }
    if($threshold -gt 128) {
        $threshold = 128
        $syncHash.Gui.NS_Threshold.text = "128"
    }
    if($threshold -lt 1) {
        $threshold = 1
        $syncHash.Gui.NS_Threshold.text = "1"
    }

    if([string]::IsNullOrEmpty($syncHash.Gui.TB_NS_IP.text)){
        $msg = "  $Global:emoji_hand IP address is blank."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true

        return
    }

    if(!(Test-IPAddress($syncHash.Gui.TB_NS_IP.text))){
        $msg = "  $Global:emoji_hand Illegal IP address detected."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true

        return
    }

    [string]$ip = $syncHash.GUI.TB_NS_IP.text
    if($syncHash.GUI.rb_NS_Mask.IsChecked){
        if([string]::IsNullOrEmpty($syncHash.Gui.TB_NS_Mask.text)){
            $msg = "  $Global:emoji_hand Network mask is blank."
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text $msg -NewLine $true
    
            return
        }

        if(!(ValidateSubnetMask($syncHash.Gui.TB_NS_Mask.text))) {
            $msg = "  $Global:emoji_hand Illegal subnet mask detected."
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true

            return
        }

        if(!($syncHash.Gui.TB_NS_Mask.text.SubString(0,8) -eq '255.255.')){
            $msg = "IP range too large to handle. [CIDR >= 16] or [Subnet Mask >= 255.255.0.0]"
            Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text $msg -NewLine $true
            return
        }

        $mask = ($syncHash.GUI.TB_NS_Mask.text)

        $range = Get-IPrangeStartEnd -ip $ip -mask $mask

        Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "--------------------------" -NewLine $true

        $msg = "Start IP = " + $range.Start
        Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text $msg -NewLine $true

        $msg = "End IP   = " + $range.end
        Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text $msg -NewLine $true
    }
    
    if($syncHash.GUI.rb_NS_CIDR.IsChecked){
        if([string]::IsNullOrEmpty($syncHash.Gui.TB_NS_CIDR.text)){
            $msg = "  $Global:emoji_hand CIDR is blank."
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text $msg -NewLine $true
    
            return
        }
        $cidr = $syncHash.GUI.TB_NS_CIDR.text -as [int]
        if($cidr -lt 16 -or $cidr -gt 31){
            $msg = "  $Global:emoji_hand CIDR is out of range."
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text $msg -NewLine $true
            return
        }
        $range = Get-IPrangeStartEnd -ip $ip -cidr $cidr

        Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "--------------------------" -NewLine $true

        $msg = "Start IP = " + $range.Start
        Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text $msg -NewLine $true

        $msg = "End IP   = "+$range.end
        Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text $msg -NewLine $true
    }

    Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "--------------------------" -NewLine $true

    if($syncHash.Gui.CB_ARP.IsChecked) {
        $msg = "[ARP] "
    } else {
        $msg = "[ICMP] "
    }
    Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text $msg -NewLine $false
    $msg = "Creating worker threads with threshold $threshold ..."
    Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text $msg -NewLine $true

    Invoke-Command $syncHash.Devider_scriptblock

    # Disable wedgets
    $syncHash.GUI.btn_Scan.IsEnabled = $false
    $syncHash.GUI.btn_Ping.IsEnabled = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.scan_scriptblock).AddArgument($range.Start).AddArgument($range.end).AddArgument($threshold).AddArgument($syncHash.GUI.cb_More.IsChecked).AddArgument($syncHash.Gui.cb_arp.IsChecked)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Test Pending Reboot
$syncHash.TestPendingReboot_Scriptblock = {
    param(
        [string]$cn
    )

    function Test-PendingReboot
    {
        [CmdletBinding()]
        param
        (
            [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            [Alias("CN", "Computer")]
            [String[]]
            $ComputerName = $env:COMPUTERNAME,

            [Parameter()]
            [System.Management.Automation.PSCredential]
            [System.Management.Automation.CredentialAttribute()]
            $Credential,

            [Parameter()]
            [Switch]
            $Detailed,

            [Parameter()]
            [Switch]
            $SkipConfigurationManagerClientCheck,

            [Parameter()]
            [Switch]
            $SkipPendingFileRenameOperationsCheck
        )

        process
        {
            foreach ($computer in $ComputerName)
            {
                try
                {
                    $invokeWmiMethodParameters = @{
                        Namespace    = 'root/default'
                        Class        = 'StdRegProv'
                        Name         = 'EnumKey'
                        ComputerName = $computer
                        ErrorAction  = 'Stop'
                    }

                    $hklm = [UInt32] "0x80000002"

                    if ($PSBoundParameters.ContainsKey('Credential'))
                    {
                        $invokeWmiMethodParameters.Credential = $Credential
                    }

                    ## Query the Component Based Servicing Reg Key
                    $invokeWmiMethodParameters.ArgumentList = @($hklm, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\')
                    $registryComponentBasedServicing = (Invoke-WmiMethod @invokeWmiMethodParameters).sNames -contains 'RebootPending'

                    ## Query WUAU from the registry
                    $invokeWmiMethodParameters.ArgumentList = @($hklm, 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\')
                    $registryWindowsUpdateAutoUpdate = (Invoke-WmiMethod @invokeWmiMethodParameters).sNames -contains 'RebootRequired'

                    ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
                    $invokeWmiMethodParameters.ArgumentList = @($hklm, 'SYSTEM\CurrentControlSet\Services\Netlogon')
                    $registryNetlogon = (Invoke-WmiMethod @invokeWmiMethodParameters).sNames
                    $pendingDomainJoin = ($registryNetlogon -contains 'JoinDomain') -or ($registryNetlogon -contains 'AvoidSpnSet')

                    ## Query ComputerName and ActiveComputerName from the registry and setting the MethodName to GetMultiStringValue
                    $invokeWmiMethodParameters.Name = 'GetMultiStringValue'
                    $invokeWmiMethodParameters.ArgumentList = @($hklm, 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\', 'ComputerName')
                    $registryActiveComputerName = Invoke-WmiMethod @invokeWmiMethodParameters

                    $invokeWmiMethodParameters.ArgumentList = @($hklm, 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\', 'ComputerName')
                    $registryComputerName = Invoke-WmiMethod @invokeWmiMethodParameters

                    $pendingComputerRename = $registryActiveComputerName -ne $registryComputerName -or $pendingDomainJoin

                    ## Query PendingFileRenameOperations from the registry
                    if (-not $PSBoundParameters.ContainsKey('SkipPendingFileRenameOperationsCheck'))
                    {
                        $invokeWmiMethodParameters.ArgumentList = @($hklm, 'SYSTEM\CurrentControlSet\Control\Session Manager\', 'PendingFileRenameOperations')
                        $registryPendingFileRenameOperations = (Invoke-WmiMethod @invokeWmiMethodParameters).sValue
                        $registryPendingFileRenameOperationsBool = [bool]$registryPendingFileRenameOperations
                    }

                    ## Query ClientSDK for pending reboot status, unless SkipConfigurationManagerClientCheck is present
                    if (-not $PSBoundParameters.ContainsKey('SkipConfigurationManagerClientCheck'))
                    {
                        $invokeWmiMethodParameters.NameSpace = 'ROOT\ccm\ClientSDK'
                        $invokeWmiMethodParameters.Class = 'CCM_ClientUtilities'
                        $invokeWmiMethodParameters.Name = 'DetermineifRebootPending'
                        $invokeWmiMethodParameters.Remove('ArgumentList')

                        try
                        {
                            $sccmClientSDK = Invoke-WmiMethod @invokeWmiMethodParameters
                            $systemCenterConfigManager = $sccmClientSDK.ReturnValue -eq 0 -and ($sccmClientSDK.IsHardRebootPending -or $sccmClientSDK.RebootPending)
                        }
                        catch
                        {
                            $systemCenterConfigManager = $null
                            Write-Verbose -Message ($script:localizedData.invokeWmiClientSDKError -f $computer)
                        }
                    }

                    $isRebootPending = $registryComponentBasedServicing -or `
                        $pendingComputerRename -or `
                        $pendingDomainJoin -or `
                        $registryPendingFileRenameOperationsBool -or `
                        $systemCenterConfigManager -or `
                        $registryWindowsUpdateAutoUpdate

                    $ArrayList = New-Object System.Collections.ArrayList

                    if ($PSBoundParameters.ContainsKey('Detailed'))
                    {
                        $ArrayList.Add("ComputerName                     = $computer")
                        $ArrayList.Add("ComponentBasedServicing          = $registryComponentBasedServicing")
                        $ArrayList.Add("PendingComputerRenameDomainJoin  = $pendingComputerRename")
                        $ArrayList.Add("PendingFileRenameOperations      = $registryPendingFileRenameOperationsBool")
                        $ArrayList.Add("PendingFileRenameOperationsValue = $registryPendingFileRenameOperations")
                        $ArrayList.Add("PendingFileRenameOperationsValue = $registryPendingFileRenameOperations")
                        $ArrayList.Add("WindowsUpdateAutoUpdate          = $registryWindowsUpdateAutoUpdate")
                        $ArrayList.Add("IsRebootPending                  = $isRebootPending")
                        
                        [PSCustomObject]@{
                            ComputerName                     = $computer
                            ComponentBasedServicing          = $registryComponentBasedServicing
                            PendingComputerRenameDomainJoin  = $pendingComputerRename
                            PendingFileRenameOperations      = $registryPendingFileRenameOperationsBool
                            PendingFileRenameOperationsValue = $registryPendingFileRenameOperations
                            SystemCenterConfigManager        = $systemCenterConfigManager
                            WindowsUpdateAutoUpdate          = $registryWindowsUpdateAutoUpdate
                            IsRebootPending                  = $isRebootPending
                        }
                    }
                    else
                    {
                        $ArrayList.Add("ComputerName    = $computer")
                        $ArrayList.Add("IsRebootPending = $isRebootPending")
                        [PSCustomObject]@{
                            ComputerName    = $computer
                            IsRebootPending = $isRebootPending
                        }
                    }

                    $ArrayList | ForEach-Object {
                        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$_,$true
                    }
                    $msg = "================================================================================"
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Cyan",$msg,$true
                }
                catch
                {
                    $msg = "$Computer`: $_"
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Red",$msg,$true
                }
            }
            Remove-Variable -Name "computer" 2>$null
            Remove-Variable -Name "invokeWmiMethodParameters" 2>$null
            Remove-Variable -Name "hklm" 2>$null
            Remove-Variable -Name "registryComponentBasedServicing" 2>$null
            Remove-Variable -Name "registryWindowsUpdateAutoUpdate" 2>$null
            Remove-Variable -Name "registryNetlogon" 2>$null
            Remove-Variable -Name "pendingDomainJoin" 2>$null
            Remove-Variable -Name "registryActiveComputerName" 2>$null
            Remove-Variable -Name "registryComputerName" 2>$null
            Remove-Variable -Name "pendingComputerRename" 2>$null
            Remove-Variable -Name "registryPendingFileRenameOperations" 2>$null
            Remove-Variable -Name "registryPendingFileRenameOperationsBool" 2>$null
            Remove-Variable -Name "sccmClientSDK" 2>$null
            Remove-Variable -Name "systemCenterConfigManager" 2>$null
            Remove-Variable -Name "isRebootPending" 2>$null
            Remove-Variable -Name "registryWindowsUpdateAutoUpdate" 2>$null
            Remove-Variable -Name "ArrayList" 2>$null
            Remove-Variable -Name "msg" 2>$null
        }
    }

    Test-PendingReboot -ComputerName $cn -Detailed

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    $syncHash.control.TestPendingReboot_Scriptblock_completed = $true
}

# Handle Pending Reboot Test Event
$syncHash.GUI.btn_PendingReboot.Add_Click({
    $cn = $syncHash.Gui.cb_Target.Text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0059]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "The target is not alive." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # Disable wedgets
    $syncHash.GUI.btn_PendingReboot.IsEnabled = $false
    $syncHash.GUI.btn_Reboot.IsEnabled = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.TestPendingReboot_Scriptblock).AddArgument($cn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.reboot_scriptblock = {
    param (
        [string]$cn,
        [PSCredential]$cd,
        [Bool]$CurrentUser
    )

    try {
        if($CurrentUser) {
            Restart-Computer -ComputerName $cn -Force
        } else {
            Restart-Computer -ComputerName $cn -Credential $cd -Force
        }
        
        $msg = "Reboot command has been sent to $cn"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","LightGreen",$msg,$true
    } catch {
        $e = "[Error 0060]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "e" 2>$null
    Remove-Variable -Name "msg" 2>$null
    
    $syncHash.control.TestPendingReboot_Scriptblock_completed = $true
}

# Handle reboot button click event
$syncHash.GUI.btn_Reboot.Add_Click({
    [PSCredential]$cred = $null

    $cn = $syncHash.Gui.cb_Target.Text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0061]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "The target is not alive." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    if(!($syncHash.GUI.cb_CurrentUser.IsChecked)) {
        $cred = Get-Credential -Message "The credential to reboot the target machine:"
        if(!($cred)) {
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "No credential provided." -NewLine $true
            return
        }
    }

    # Disable wedgets
    $syncHash.GUI.btn_PendingReboot.IsEnabled = $false
    $syncHash.GUI.btn_Reboot.IsEnabled = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.reboot_Scriptblock).AddArgument($cn).AddArgument($cred).AddArgument($syncHash.GUI.cb_CurrentUser.IsChecked)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.TCP_Ping_scriptblock = {
    param(
        [string]$ip,
        [int]$port
    )

    try{
        $ProgressPreference = 'SilentlyContinue' # Supress the popup window

        $test = Test-NetConnection -ComputerName $ip -Port $port -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

        $msg = " Remote node $ip is listening on TCP port $port : "
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

        $msg = ($test).ToString()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$msg,$true
    } catch {
        $e = "[Error 0062]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "e" 2>$null
    Remove-Variable -Name "test" 2>$null
    Remove-Variable -Name "msg" 2>$null
    Remove-Variable -Name "PregressPreference" 2>$null

    $syncHash.control.scan_scriptblock_completed = $true
}

# Ping TCP Port handler
$syncHash.GUI.btn_Ping.Add_Click({
    [int]$port = $syncHash.Gui.NS_TCP_Port.text -as [int]
    if(($port -gt 65535) -or ($port -le 0) -or ($port -eq $null)){
        Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "  $Global:emoji_hand Port number out of range [1..65535]." -NewLine $true
        return
    }

    [string]$ip = $syncHash.Gui.cb_Target.text
    if([string]::IsNullOrEmpty($ip)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.GUI.btn_Scan.IsEnabled = $false
    $syncHash.GUI.btn_Ping.IsEnabled = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.TCP_Ping_scriptblock).AddArgument($ip).AddArgument($port)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Open C drive on the target
$syncHash.GUI.btn_cDrive.Add_Click({
    $path = "\\" + $syncHash.Gui.cb_Target.text + "\C$"

    if([string]::IsNullOrEmpty($syncHash.Gui.cb_Target.text)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    } else {
        if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
            $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
        }
    }

    try{
        Start-Process -FilePath "explorer.exe" -ArgumentList $path -Verb RunAs -ErrorAction SilentlyContinue
    } catch {
        $e = "[Error 0063]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
})

$syncHash.List_scriptblock = {
    param(
        [string]$cn
    )

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","20","Yellow","Local Administrators Group members on $cn :",$true
    try{
        $group = [ADSI]"WinNT://$cn/Administrators"
        $members = @($group.Invoke("Members"))
        foreach ($member in $members) {
            $MemberName = $member.GetType().Invokemember("Name","GetProperty",$null,$member,$null)
            [ADSI]$LocalUser = "WinNT://$cn/$MemberName,user"
            if($LocalUser.Name -ne $null){
                $local = "  (Local)"
            }
            if($LocalUser.Name -ne $null){
                $NL = $False
            } else {
                $NL = $true
            }
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$MemberName,$NL

            if($LocalUser.Name -ne $null){
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$local,$true
            }
        }
        $msg = "--== End of the list ==--"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
    } catch {
        $e = "[Error 0064]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "group" 2>$null
    Remove-Variable -Name "members" 2>$null
    Remove-Variable -Name "member" 2>$null
    Remove-Variable -Name "MemberName" 2>$null
    Remove-Variable -Name "LocalUser" 2>$null
    Remove-Variable -Name "local" 2>$null
    Remove-Variable -Name "NL" 2>$null
    Remove-Variable -Name "msg" 2>$null
    Remove-Variable -Name "e" 2>$null

    $syncHash.control.grant_scriptblock_completed = $true
}

# List admin group members remotely
$syncHash.GUI.btn_List.Add_Click({
    $cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($syncHash.Gui.cb_Target.text)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    } else {
        if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
            $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
        }
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0065]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }
    
    # Disable wedgets
    $syncHash.Gui.btn_Load.IsEnabled   = $False
    $syncHash.Gui.btn_clr.IsEnabled    = $False
    $syncHash.Gui.btn_Add.IsEnabled    = $False
    $syncHash.Gui.btn_Grant.IsEnabled  = $False
    $syncHash.Gui.btn_Remove.IsEnabled = $False
    $syncHash.Gui.btn_List.IsEnabled   = $False
    $syncHash.Gui.btn_Reset.IsEnabled  = $False
    $syncHash.Gui.btn_Test.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.List_scriptblock).AddArgument($cn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Add a user to the list
$syncHash.GUI.btn_Add.Add_Click({
    [string]$u = $syncHash.Gui.tb_User.text
    [string]::IsNullOrEmpty($u)
    if([string]::IsNullOrEmpty($u)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_angry Nothing to add." -NewLine $true
        return
    }
    if(($syncHash.Gui.lb_UserList.items.contains($u))){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_angry The user is already in the list." -NewLine $true
    } else {
        $syncHash.Gui.lb_UserList.items.add($u)
    }
    $syncHash.GUI.tb_User.text = ""
})

# Clear the user list
$syncHash.GUI.btn_clr.Add_Click({
    $syncHash.Gui.lb_UserList.items.Clear()
})

$syncHash.Reset_scriptblock = {
    param(
        [PSCredential]$credential,
        [string]$cn,
        [string]$user
    )

    $usr = [adsi]"WinNT://$cn/$($credential.GetNetworkCredential().Username),user"
    $usr.SetPassword($credential.GetNetworkCredential().Password)
    $usr.SetInfo()
    Show-Result -Font "Courier New" -Size "18" -Color "LightGreen" -Text "The local user $user's password had been reset." -NewLine $true
    Show-Result -Font "Courier New" -Size "18" -Color "LightGreen" -Text "Validating the password ...   " -NewLine $False
    $pw = $credential.GetNetworkCredential().password
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $obj = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$cn)
    [bool]$ok = $obj.ValidateCredentials($user, $pw)
    if($ok){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Success",$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","Failed",$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "usr" 2>$null
    Remove-Variable -Name "pw" 2>$null
    Remove-Variable -Name "obj" 2>$null
    Remove-Variable -Name "ok" 2>$null

    $syncHash.control.grant_scriptblock_completed = $true
}

# Reset local admin password (non-domain users)
$syncHash.GUI.btn_Reset.Add_Click({
    $cn = $syncHash.Gui.cb_Target.text
    $user = $syncHash.GUI.tb_LocalUser.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($user)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand User is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0066]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    $credential = Get-Credential -UserName $user -Message "Enter new password"
    If ($credential -eq $null) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The username and/or the password is empty!" -NewLine $true
        return
    }
    
    Show-Result -Font "Courier New" -Size "18" -Color "LightGreen" -Text "Resetting $user's password ...         " -NewLine $false

    # Disable wedgets
    $syncHash.Gui.btn_Load.IsEnabled   = $False
    $syncHash.Gui.btn_clr.IsEnabled    = $False
    $syncHash.Gui.btn_Add.IsEnabled    = $False
    $syncHash.Gui.btn_Grant.IsEnabled  = $False
    $syncHash.Gui.btn_Remove.IsEnabled = $False
    $syncHash.Gui.btn_List.IsEnabled   = $False
    $syncHash.Gui.btn_Reset.IsEnabled  = $False
    $syncHash.Gui.btn_Test.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.Reset_scriptblock).AddArgument($credential).AddArgument($cn).AddArgument($user)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.Test_scriptblock = {
    param(
        [PSCredential]$credential,
        [string]$cn,
        [string]$user
    )

    $pw = $credential.GetNetworkCredential().password
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $obj = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$cn)
    [bool]$ok = $obj.ValidateCredentials($user, $pw)
    if($ok){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Success",$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","Failed",$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "pw" 2>$null
    Remove-Variable -Name "obj" 2>$null
    Remove-Variable -Name "ok" 2>$null

    $syncHash.control.grant_scriptblock_completed = $true
}

# Test local admin password (non-domain users)
$syncHash.GUI.btn_Test.Add_Click({
    $cn = $syncHash.Gui.cb_Target.text
    $user = $syncHash.GUI.tb_LocalUser.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($user)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand User is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0067]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    $credential = Get-Credential -UserName $user -Message "Enter new password"
    If ($credential -eq $null) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The username and/or the password is empty!" -NewLine $true
        return
    }

    Show-Result -Font "Courier New" -Size "18" -Color "LightGreen" -Text "Trying to authenticate with the password ... " -NewLine $False

    # Disable wedgets
    $syncHash.Gui.btn_Load.IsEnabled   = $False
    $syncHash.Gui.btn_clr.IsEnabled    = $False
    $syncHash.Gui.btn_Add.IsEnabled    = $False
    $syncHash.Gui.btn_Grant.IsEnabled  = $False
    $syncHash.Gui.btn_Remove.IsEnabled = $False
    $syncHash.Gui.btn_List.IsEnabled   = $False
    $syncHash.Gui.btn_Reset.IsEnabled  = $False
    $syncHash.Gui.btn_Test.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.Test_scriptblock).AddArgument($credential).AddArgument($cn).AddArgument($user)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Get Local Admin Password
$syncHash.GUI.btn_AdmPwd.Add_Click({
    $cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    try{
        $Result = get-ADComputer $cn  -Properties *
    }catch{
        Show-Result -Font "Courier New" -Size "30" -Color "Yellow" -Text "Computer '$cn' not found in AD." -NewLine $true
        return
    }
    $Password = $Result | Select-Object -ExpandProperty ms-Mcs-AdmPwd
    $Expire = $Result | Select-Object -ExpandProperty ms-Mcs-AdmPwdExpirationTime
    $eTime = [datetime]::FromFileTime([convert]::ToInt64($Expire,10))
    Show-Result -Font "Courier New" -Size "30" -Color "Yellow" -Text "------------------------------" -NewLine $true
    Show-Result -Font "Courier New" -Size "30" -Color "Cyan" -Text "Password = $Password" -NewLine $true
    Show-Result -Font "Courier New" -Size "30" -Color "Cyan" -Text "Expire   = $eTime" -NewLine $true
    Show-Result -Font "Courier New" -Size "30" -Color "Yellow" -Text "------------------------------" -NewLine $true

    Remove-Variable -Name "cn"
    Remove-Variable -Name "Result"
    Remove-Variable -Name "Password"
    Remove-Variable -Name "Expire"
    Remove-Variable -Name "eTime"
})

# Add user to local RDP group
$syncHash.GUI.btn_RDPAdd.Add_Click({
    [string]$cn  = $syncHash.Gui.cb_Target.text
    [string]$sam = $syncHash.Gui.tb_SamName.text
    [pscredential]$cred = $syncHash.PSRemote_credential

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($sam)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Sam account name is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0068]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]

        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true

        return
    }

    try{
        if($cred){
            $Session = New-PSSession -ComputerName $cn -Credential $cred
        } else {
            $Session = New-PSSession -ComputerName $cn
        }
    } catch {
        $e = "[Error 0069]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        $msg = "Error: Cannot establish remote session with $cn, workflow terminated."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$error[0],$true
        return
    }

    $RST = invoke-command -Session $Session -ScriptBlock {
        Add-LocalGroupMember -Group "Remote Desktop Users" -Member $using:sam -ErrorAction SilentlyContinue
        $error[0]
    }
    Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text "Command sent, please check the list." -NewLine $true
    Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text $RST -NewLine $true
})

# Remove user from local RDP group
$syncHash.GUI.btn_RDPRemove.Add_Click({
    [string]$cn  = $syncHash.Gui.cb_Target.text
    [string]$sam = $syncHash.Gui.tb_SamName.text
    [pscredential]$cred = $syncHash.PSRemote_credential

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($sam)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Sam account name is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0070]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]

        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true

        return
    }

    try{
        if($cred){
            $Session = New-PSSession -ComputerName $cn -Credential $cred
        } else {
            $Session = New-PSSession -ComputerName $cn
        }
    } catch {
        $e = "[Error 0071]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        $msg = "Error: Cannot establish remote session with $cn, workflow terminated."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$error[0],$true
        return
    }

    $RST = invoke-command -Session $Session -ScriptBlock {
        Remove-LocalGroupMember -Group "Remote Desktop Users" -Member $using:sam -ErrorAction SilentlyContinue
        $error[0]
    }
    Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text "Command sent, please check the list." -NewLine $true
    Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text $RST -NewLine $true
})
# List users in local RDP group
$syncHash.GUI.btn_RDPList.Add_Click({
    [string]$cn  = $syncHash.Gui.cb_Target.text
    [pscredential]$cred = $syncHash.PSRemote_credential

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0072]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]

        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true

        return
    }

    try{
        if($cred){
            $Session = New-PSSession -ComputerName $cn -Credential $cred
        } else {
            $Session = New-PSSession -ComputerName $cn
        }
    } catch {
        $e = "[Error 0073]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        $msg = "Error: Cannot establish remote session with $cn, workflow terminated."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$error[0],$true
        return
    }

    $rst = invoke-command -Session $Session -ScriptBlock {
        Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
    }

    if(!$rst){
        Show-Result -Font "Courier New" -Size "18" -Color "Yellowe" -Text "Nobody is in the list." -NewLine $true
        return
    }
    if(!(($rst.gettype()).Name -eq "String")){
        $rst = $rst | Out-String
    }
    $rst = $rst -replace "`n",""
    Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text $rst -NewLine $true
})

# Test PSRemoting
$syncHash.GUI.btn_TestPSR.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0074]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        Remove-Variable -Name "e" 2>$null
        Remove-Variable -Name "test" 2>$null
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        Remove-Variable -Name "test" 2>$null
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    $r = Test-Wsman -ComputerName $cn 2>&1

    if($r){
        [bool]$failed = $false
        if($r.wsmid){
            Show-Result -Font "Courier New" -Size "18" -Color "LightGreen" -Text  "wsmid           : " -NewLine $false
            Show-Result -Font "Courier New" -Size "18" -Color "Cyan"  -Text  $r.wsmid -NewLine $true
        } else {
            $failed = $true
        }
        if($r.ProtocolVersion){
            Show-Result -Font "Courier New" -Size "18" -Color "LightGreen" -Text  "ProtocolVersion : " -NewLine $false
            Show-Result -Font "Courier New" -Size "18" -Color "Cyan"  -Text  $r.ProtocolVersion -NewLine $true
        } else {
            $failed = $true
        }
        if($r.ProductVendor){
            Show-Result -Font "Courier New" -Size "18" -Color "LightGreen" -Text  "ProductVendor   : " -NewLine $false
            Show-Result -Font "Courier New" -Size "18" -Color "Cyan"  -Text  $r.ProductVendor -NewLine $true
        } else {
            $failed = $true
        }
        if($r.ProductVersion){
            Show-Result -Font "Courier New" -Size "18" -Color "LightGreen" -Text  "ProductVersion  : " -NewLine $false
            Show-Result -Font "Courier New" -Size "18" -Color "Cyan"  -Text  $r.ProductVersion -NewLine $true
        } else {
            $failed = $true
        }
        if($failed){
            $e = "[Error 0075]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            Show-Result -Font "Courier New" -Size "18" -Color "Yellow"  -Text  " --== PSRemoting is not enabled on $cn ==-- $Global:emoji_error" -NewLine $true
        } else {
            Show-Result -Font "Courier New" -Size "18" -Color "LightGreen"  -Text  " --== PSRemoting is enabled on $cn ==-- $Global:emoji_check" -NewLine $true
        }
    } else {
        $e = "[Error 0076]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        Show-Result -Font "Courier New" -Size "18" -Color "Yellow"  -Text  " --== PSRemoting is not enabled on $cn ==-- $Global:emoji_error" -NewLine $true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "e" 2>$null
    Remove-Variable -Name "test" 2>$null
    Remove-Variable -Name "r" 2>$null
    Remove-Variable -Name "failed" 2>$null
})

$syncHash.EnablePSRemoting_scriptblock = {
    param (
        [string]$cn
    )

    $r = Start-Process -Filepath "psexec.exe" -Argumentlist "/accepteula /nobanner \\$cn -h -d winrm.cmd quickconfig -q" -NoNewWindow -Wait -PassThru
    if($r){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","... Configure WinRM Done",$true
    }
    $r = Start-Process -Filepath "psexec.exe" -Argumentlist "/accepteula /nobanner \\$cn -h -d powershell.exe enable-psremoting -force" -NoNewWindow -Wait -PassThru
    if($r){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","... Enable-PSRemoting Done",$true
    }
    $r = Start-Process -Filepath "psexec.exe" -Argumentlist "/accepteula /nobanner \\$cn -h -d powershell.exe set-executionpolicy RemoteSigned -force" -NoNewWindow -Wait -PassThru
    if($r){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","... Set-ExecutionPolicy Done",$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","All commands sent, please test it.",$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "r" 2>$null

    $syncHash.control.EnablePSRemoting_scriptblock_completed = $true
}

# Enable PSRemoting
$syncHash.GUI.btn_Enable.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0077]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # Disable wedgets
    $syncHash.Gui.btn_Enable.IsEnabled   = $False
    $syncHash.Gui.btn_TestPSR.IsEnabled  = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.EnablePSRemoting_scriptblock).AddArgument($cn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.Gui.Svs.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    
    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0078]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "Fetching data, please stand by ..." -NewLine $true

    services.msc /computer=$cn
})

$syncHash.ListServices_scriptblock = {
    [CmdletBinding()]
    param(
        [string]$cn
    )

    [string]$list = ""
    [string]$prefix = ""
    [string]$bb= ""
    [string]$m = ""
    [int]$i = 0

    try{
        $list = get-service -ComputerName $cn | Select-Object -Property Name,StartType,Status,DisplayName | Format-Table -AutoSize | Out-String
    } catch {
        $e = "[Error 0079]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","Failed to get the service list from $cn.",$true

        $syncHash.control.ListServices_scriptblock_completed = $true 
        return
    }

    if($list){
        $aa = $list.Split("`n")
        
        for($i=0;$i -lt $aa.length;$i++) {
            $bb = $aa[$i].Trim()
            if($bb) {
                if(($i -eq 0) -or ($i -eq 1) -or ($i -eq 2)) {
                    $prefix = "      "
                } else {
                    $prefix = "[" + ((($i-2).tostring()).trim()).PadLeft(3, ' ') + "] "
                }
                $m = $prefix + $bb
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$m,$true
            }
        }
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan"," -= End of the list =-",$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","Service $sn not found.",$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "list" 2>$null
    Remove-Variable -Name "prefix" 2>$null
    Remove-Variable -Name "bb" 2>$null
    Remove-Variable -Name "m" 2>$null
    Remove-Variable -Name "i" 2>$null
    Remove-Variable -Name "aa" 2>$null
    Remove-Variable -Name "e" 2>$null

    $syncHash.control.ListServices_scriptblock_completed = $true 
}

# List services
$syncHash.GUI.btn_sList.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0080]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "Fetching data, please stand by ..." -NewLine $true

    # Disable wedgets
    $syncHash.Gui.btn_sStart.IsEnabled   = $False
    $syncHash.Gui.btn_sStop.IsEnabled    = $False
    $syncHash.Gui.btn_sRestart.IsEnabled = $False
    $syncHash.Gui.btn_sList.IsEnabled    = $False
    $syncHash.Gui.btn_sQuery.IsEnabled   = $False
    $syncHash.Gui.btn_sChange.IsEnabled  = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.ListServices_scriptblock).AddArgument($cn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.ChangeService_scriptblock = {
    param (
        [string]$cn, # Computer name
        [string]$sn,  # Service name
        [string]$StartType
    )

    [bool]$ok = $true
    [string]$e = ""

    $service = get-service -ComputerName $cn -Name $sn
    if($service){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen","Changing Startup type to $StartType : ",$false
        try{
            Set-Service -InputObject $service -StartupType $StartType
        } catch {
            $e = "[Error 0081]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            $ok = $false
        } 
        if($ok) {
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Successfull",$true
        } else {
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","Failed",$true
        }

        $service = get-service -ComputerName $cn -Name $sn
        $tmp = ($service.StartType).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen","Startup type of Service $sn on $cn is ",$false
        if($tmp -match "Disabled"){
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$tmp,$true
        } 
        if($tmp -match "Manual") {
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$tmp,$true
        }
        if($tmp -match "Automatic") {
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$tmp,$true
        }
    } else {
        $tmp = "Cannot find the service $sn on $cn, please check the name and try again."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$tmp,$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "service" 2>$null
    Remove-Variable -Name "tmp" 2>$null
    Remove-Variable -Name "ok" 2>$null
    Remove-Variable -Name "e" 2>$null

    $syncHash.control.Service_scriptblock_completed = $true
}

$syncHash.GUI.btn_sChange.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$sn = $syncHash.Gui.tb_ServiceName.text
    [string]$type = ""

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($sn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Service Name is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0082]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    if($syncHash.Gui.cb_SType.SelectedIndex -eq 0) { $type = "Automatic" }
    if($syncHash.Gui.cb_SType.SelectedIndex -eq 1) { $type = "Manual" }
    if($syncHash.Gui.cb_SType.SelectedIndex -eq 2) { $type = "Disabled" }

    # Disable wedgets
    $syncHash.Gui.btn_sStart.IsEnabled   = $False
    $syncHash.Gui.btn_sStop.IsEnabled    = $False
    $syncHash.Gui.btn_sRestart.IsEnabled = $False
    $syncHash.Gui.btn_sList.IsEnabled    = $False
    $syncHash.Gui.btn_sQuery.IsEnabled   = $False
    $syncHash.Gui.btn_sChange.IsEnabled  = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.ChangeService_scriptblock).AddArgument($cn).AddArgument($sn).AddArgument($type)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.ServiceQuery_scriptblock = {
    param (
        [string]$cn, # Computer name
        [string]$sn  # Service name
    )

    [string]$list = ""

    $list = get-service -ComputerName $cn|  Where-Object {$_.Name -match $sn} | Select-Object -Property Name,StartType,Status,DisplayName,DependentServices | Format-Table -AutoSize | Out-String
    if($list){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Service query on $cn",$true
        $a = $list.Split("`n")
        [int]$i = 0
        $a | ForEach-Object {
            $i++
            $b = $_.Trim()
            if($b) {
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
            }
        }
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan"," -= End of the list =-",$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","Service $sn not found.",$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "list" 2>$null
    Remove-Variable -Name "a" 2>$null
    Remove-Variable -Name "b" 2>$null
    Remove-Variable -Name "i" 2>$null

    $syncHash.control.Service_scriptblock_completed = $true
}

# Query a service
$syncHash.GUI.btn_sQuery.Add_Click({
    [string]$cn      = $syncHash.Gui.cb_Target.text
    [string]$service = $syncHash.Gui.tb_ServiceName.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($service)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Service Name is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0083]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # Disable wedgets
    $syncHash.Gui.btn_sStart.IsEnabled   = $False
    $syncHash.Gui.btn_sStop.IsEnabled    = $False
    $syncHash.Gui.btn_sRestart.IsEnabled = $False
    $syncHash.Gui.btn_sList.IsEnabled    = $False
    $syncHash.Gui.btn_sQuery.IsEnabled   = $False
    $syncHash.Gui.btn_sChange.IsEnabled  = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.ServiceQuery_scriptblock).AddArgument($cn).AddArgument($service)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.StartService_scriptblock = {
    param (
        [string]$cn, # Computer name
        [string]$sn  # Service name
    )

    $service = get-service -ComputerName $cn -Name $sn
    if($service){
        Set-Service -InputObject $service -Status Running -StartupType Automatic
        Start-Service -InputObject $service
        $service = get-service -ComputerName $cn -Name $sn
        $tmp = ($service.status).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen","Service $sn on $cn is   ",$false
        if($tmp -match "Stopped"){
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$tmp,$true
        } else {
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$tmp,$true
        }
    } else {
        $tmp = "Cannot find the service $sn on $cn, please check the name and try again."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$tmp,$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "service" 2>$null
    Remove-Variable -Name "tmp" 2>$null

    $syncHash.control.Service_scriptblock_completed = $true
}

$syncHash.GUI.btn_sStart.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$sn = $syncHash.Gui.tb_ServiceName.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($sn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Service Name is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0084]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # Disable wedgets
    $syncHash.Gui.btn_sStart.IsEnabled   = $False
    $syncHash.Gui.btn_sStop.IsEnabled    = $False
    $syncHash.Gui.btn_sRestart.IsEnabled = $False
    $syncHash.Gui.btn_sList.IsEnabled    = $False
    $syncHash.Gui.btn_sQuery.IsEnabled   = $False
    $syncHash.Gui.btn_sChange.IsEnabled  = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.StartService_scriptblock).AddArgument($cn).AddArgument($sn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.StopService_scriptblock = {
    param (
        [string]$cn, # Computer name
        [string]$sn  # Service name
    )

    $service = get-service -ComputerName $cn -Name $sn

    if($service){
        Stop-Service -InputObject $service
        $service = get-service -ComputerName $cn -Name $sn
        $tmp = ($service.status).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen","Service $sn on $cn is   ",$false
        if($tmp -match "Stopped"){
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$tmp,$true
        } else {
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$tmp,$true
        }
    } else {
        $tmp = "Cannot find the service $sn on $cn, please check the name and try again."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$tmp,$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "service" 2>$null
    Remove-Variable -Name "tmp" 2>$null

    $syncHash.control.Service_scriptblock_completed = $true
}

$syncHash.GUI.btn_sStop.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$sn = $syncHash.Gui.tb_ServiceName.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($sn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Service Name is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0085]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # Disable wedgets
    $syncHash.Gui.btn_sStart.IsEnabled   = $False
    $syncHash.Gui.btn_sStop.IsEnabled    = $False
    $syncHash.Gui.btn_sRestart.IsEnabled = $False
    $syncHash.Gui.btn_sList.IsEnabled    = $False
    $syncHash.Gui.btn_sQuery.IsEnabled   = $False
    $syncHash.Gui.btn_sChange.IsEnabled  = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.StopService_scriptblock).AddArgument($cn).AddArgument($sn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.RestartService_scriptblock = {
    param (
        [string]$cn, # Computer name
        [string]$sn  # Service name
    )

    $service = get-service -ComputerName $cn -Name $sn

    $service = get-service -ComputerName $cn -Name $sn

    if($service){
        Restart-Service -InputObject $service
        $service = get-service -ComputerName $cn -Name $sn
        $tmp = ($service.status).tostring()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen","Service $sn on $cn is   ",$false
        if($tmp -match "Stopped"){
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$tmp,$true
        } else {
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$tmp,$true
        }
    } else {
        $tmp = "Cannot find the service $sn on $cn, please check the name and try again."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$tmp,$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "service" 2>$null
    Remove-Variable -Name "tmp" 2>$null

    $syncHash.control.Service_scriptblock_completed = $true
}

$syncHash.GUI.btn_sRestart.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$sn = $syncHash.Gui.tb_ServiceName.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($sn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Service Name is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0086]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # Disable wedgets
    $syncHash.Gui.btn_sStart.IsEnabled   = $False
    $syncHash.Gui.btn_sStop.IsEnabled    = $False
    $syncHash.Gui.btn_sRestart.IsEnabled = $False
    $syncHash.Gui.btn_sList.IsEnabled    = $False
    $syncHash.Gui.btn_sQuery.IsEnabled   = $False
    $syncHash.Gui.btn_sChange.IsEnabled  = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.RestartService_scriptblock).AddArgument($cn).AddArgument($sn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Enable/Disable firewall with netsh (the thread worker)
$syncHash.FirewallNetsh_scriptblock = {
    param(
        [string]$cn,
        [bool]$domain,
        [bool]$public,
        [bool]$private,
        [bool]$enable
    )

    [string]$op = ""

    if($enable){
        $op = "on"
    } else {
        $op = "off"
    }

    if($domain) {
        $a = netsh -r $cn -c advfirewall set Domainprofile state $op
        $a | ForEach-Object {
            if($_) { $b = $_} else { $b = " "}
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
        }

        $a = netsh -r $cn -c advfirewall show domainprofile
        $a | ForEach-Object {
            if($_) { $b = $_} else { $b = " "}
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
        }
    }
    if($public) {
        $a = netsh -r $cn -c advfirewall set Publicprofile state $op
        $a | ForEach-Object {
            if($_) { $b = $_} else { $b = " "}
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
        }

        $a = netsh -r $cn -c advfirewall show publicprofile
        $a | ForEach-Object {
            if($_) { $b = $_} else { $b = " "}
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
        }
    }
    if($private) {
        $a = netsh -r $cn -c advfirewall set Privateprofile state $op
        $a | ForEach-Object {
            if($_) { $b = $_} else { $b = " "}
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
        }

        $a = netsh -r $cn -c advfirewall show privateprofile
        $a | ForEach-Object {
            if($_) { $b = $_} else { $b = " "}
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
        }
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "a" 2>$null
    Remove-Variable -Name "b" 2>$null
    Remove-Variable -Name "op" 2>$null

    $syncHash.control.Firewall_scriptblock_completed = $true
}

# Enable firewall with netsh
$syncHash.GUI.btn_fe1.Add_Click({
    [string]$cn    = $syncHash.Gui.cb_Target.text
    [bool]$domain  = $False
    [bool]$public  = $False
    [bool]$private = $False
    
    if(!($syncHash.GUI.cb_fDomain.isChecked) -and !($syncHash.GUI.cb_fPublic.isChecked) -and !($syncHash.GUI.cb_fPrivate.isChecked)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No profile selected" -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0087]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if($syncHash.GUI.cb_fDomain.isChecked) {
        $domain = $true
    } else {
        $domain = $False
    }
    if($syncHash.GUI.cb_fPublic.isChecked) {
        $public = $true
    } else {
        $public = $False
    }
    if($syncHash.GUI.cb_fPrivate.isChecked) {
        $private = $true
    } else {
        $private = $False
    }

    # Disable wedgets
    $syncHash.Gui.btn_fe1.IsEnabled   = $False
    $syncHash.Gui.btn_fe2.IsEnabled   = $False
    $syncHash.Gui.btn_fe3.IsEnabled   = $False
    $syncHash.Gui.btn_fd1.IsEnabled   = $False
    $syncHash.Gui.btn_fd2.IsEnabled   = $False
    $syncHash.Gui.btn_fd3.IsEnabled   = $False
    $syncHash.Gui.btn_fc1.IsEnabled   = $False
    $syncHash.Gui.btn_fc2.IsEnabled   = $False
    $syncHash.Gui.btn_fc3.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.FirewallNetsh_scriptblock).AddArgument($cn).AddArgument($domain).AddArgument($public).AddArgument($private).AddArgument($true)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

#Disable firewall with netsh
$syncHash.GUI.btn_fd1.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$domain  = $False
    [bool]$public  = $False
    [bool]$private = $False

    if(!($syncHash.GUI.cb_fDomain.isChecked) -and !($syncHash.GUI.cb_fPublic.isChecked) -and !($syncHash.GUI.cb_fPrivate.isChecked)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No profile selected" -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0088]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if($syncHash.GUI.cb_fDomain.isChecked) {
        $domain = $true
    } else {
        $domain = $False
    }
    if($syncHash.GUI.cb_fPublic.isChecked) {
        $public = $true
    } else {
        $public = $False
    }
    if($syncHash.GUI.cb_fPrivate.isChecked) {
        $private = $true
    } else {
        $private = $False
    }

    # Disable wedgets
    $syncHash.Gui.btn_fe1.IsEnabled   = $False
    $syncHash.Gui.btn_fe2.IsEnabled   = $False
    $syncHash.Gui.btn_fe3.IsEnabled   = $False
    $syncHash.Gui.btn_fd1.IsEnabled   = $False
    $syncHash.Gui.btn_fd2.IsEnabled   = $False
    $syncHash.Gui.btn_fd3.IsEnabled   = $False
    $syncHash.Gui.btn_fc1.IsEnabled   = $False
    $syncHash.Gui.btn_fc2.IsEnabled   = $False
    $syncHash.Gui.btn_fc3.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.FirewallNetsh_scriptblock).AddArgument($cn).AddArgument($domain).AddArgument($public).AddArgument($private).AddArgument($False)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Enable/Disable firewall with Powershell ( The thread worker )
$syncHash.FirewallPS_scriptblock = {
    param(
        [string]$cn,
        [bool]$domain,
        [bool]$public,
        [bool]$private,
        [bool]$enable,
        [pscredential]$cred
    )

    if($domain){
        if($enable){
            if($cred){
                Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Set-NetFirewallProfile -Profile Domain -Enabled True }
            } else {
                Invoke-Command -ComputerName $cn -ScriptBlock { Set-NetFirewallProfile -Profile Domain -Enabled True }
            }
        } else {
            if($cred){
                Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Set-NetFirewallProfile -Profile Domain -Enabled False }
            } else {
                Invoke-Command -ComputerName $cn -ScriptBlock { Set-NetFirewallProfile -Profile Domain -Enabled False }
            }
        }
    }

    if($public){
        if($enable){
            if($cred){
                Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Set-NetFirewallProfile -Profile Public -Enabled True }
            } else {
                Invoke-Command -ComputerName $cn -ScriptBlock { Set-NetFirewallProfile -Profile Public -Enabled True }
            }
        } else {
            if($cred){
                Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Set-NetFirewallProfile -Profile Public -Enabled False }
            } else {
                Invoke-Command -ComputerName $cn -ScriptBlock { Set-NetFirewallProfile -Profile Public -Enabled False }
            }
        }
    }

    if($private){
        if($enable){
            if($cred){
                Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Set-NetFirewallProfile -Profile Private -Enabled True }
            } else {
                Invoke-Command -ComputerName $cn -ScriptBlock { Set-NetFirewallProfile -Profile Private -Enabled True }
            }
        } else {
            if($cred){
                Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Set-NetFirewallProfile -Profile Private -Enabled False }
            } else {
                Invoke-Command -ComputerName $cn -ScriptBlock { Set-NetFirewallProfile -Profile Private -Enabled False }
            }
        }
    }

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock {get-NetFirewallProfile}
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock {get-NetFirewallProfile}
    }
    $a | ForEach-Object {
        if($_){
            $name = $_.Name.PadRight(7,' ')
            $msg = "$name : "
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$False
            if($_.enabled){
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","On",$true
            }else{
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","Off",$true
            }
        }
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "a" 2>$null
    Remove-Variable -Name "name" 2>$null

    $syncHash.control.Firewall_scriptblock_completed = $true
}

# Enable firewall with Powershell
$syncHash.GUI.btn_fe2.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$domain  = $False
    [bool]$public  = $False
    [bool]$private = $False

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if(!($syncHash.GUI.cb_fDomain.isChecked) -and !($syncHash.GUI.cb_fPublic.isChecked) -and !($syncHash.GUI.cb_fPrivate.isChecked)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No profile selected" -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0089]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if($syncHash.GUI.cb_fDomain.isChecked) {
        $domain = $true
    } else {
        $domain = $False
    }
    if($syncHash.GUI.cb_fPublic.isChecked) {
        $public = $true
    } else {
        $public = $False
    }
    if($syncHash.GUI.cb_fPrivate.isChecked) {
        $private = $true
    } else {
        $private = $False
    }

    # Disable wedgets
    $syncHash.Gui.btn_fe1.IsEnabled   = $False
    $syncHash.Gui.btn_fe2.IsEnabled   = $False
    $syncHash.Gui.btn_fe3.IsEnabled   = $False
    $syncHash.Gui.btn_fd1.IsEnabled   = $False
    $syncHash.Gui.btn_fd2.IsEnabled   = $False
    $syncHash.Gui.btn_fd3.IsEnabled   = $False
    $syncHash.Gui.btn_fc1.IsEnabled   = $False
    $syncHash.Gui.btn_fc2.IsEnabled   = $False
    $syncHash.Gui.btn_fc3.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.FirewallPS_scriptblock).AddArgument($cn).AddArgument($domain).AddArgument($public).AddArgument($private).AddArgument($true).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Disable firewall with Powershell
$syncHash.GUI.btn_fd2.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$domain  = $False
    [bool]$public  = $False
    [bool]$private = $False
    
    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if(!($syncHash.GUI.cb_fDomain.isChecked) -and !($syncHash.GUI.cb_fPublic.isChecked) -and !($syncHash.GUI.cb_fPrivate.isChecked)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No profile selected" -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0090]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if($syncHash.GUI.cb_fDomain.isChecked) {
        $domain = $true
    } else {
        $domain = $False
    }
    if($syncHash.GUI.cb_fPublic.isChecked) {
        $public = $true
    } else {
        $public = $False
    }
    if($syncHash.GUI.cb_fPrivate.isChecked) {
        $private = $true
    } else {
        $private = $False
    }

    # Disable wedgets
    $syncHash.Gui.btn_fe1.IsEnabled   = $False
    $syncHash.Gui.btn_fe2.IsEnabled   = $False
    $syncHash.Gui.btn_fe3.IsEnabled   = $False
    $syncHash.Gui.btn_fd1.IsEnabled   = $False
    $syncHash.Gui.btn_fd2.IsEnabled   = $False
    $syncHash.Gui.btn_fd3.IsEnabled   = $False
    $syncHash.Gui.btn_fc1.IsEnabled   = $False
    $syncHash.Gui.btn_fc2.IsEnabled   = $False
    $syncHash.Gui.btn_fc3.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.FirewallPS_scriptblock).AddArgument($cn).AddArgument($domain).AddArgument($public).AddArgument($private).AddArgument($False).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Enable/Disable firewall with PSexec ( The thread worker )
$syncHash.FirewallPsExec_scriptblock = {
    param(
        [string]$cn,
        [bool]$domain,
        [bool]$public,
        [bool]$private,
        [bool]$enable
    )

    [bool]$end = $false

    if($domain){
        if($enable){
            $a = PsExec.exe /accepteula /nobanner \\$cn netsh advfirewall set Domainprofile state on 2>$null
            $end = $false
            $a | ForEach-Object {
                if($_) { $b = $_} else { $b = " "}
                if(!(($b -match "Connecting") -or ($b -match "Starting") -or ($b -match "Copying")) -and (!$end)){
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
                    if($b -match "Ok") { $end = $true }
                }
            }
        } else {
            $a = PsExec.exe /accepteula /nobanner \\$cn netsh advfirewall set Domainprofile state off 2>$null
            $end = $false
            $a | ForEach-Object {
                if($_) { $b = $_} else { $b = " "}
                if(!(($b -match "Connecting") -or ($b -match "Starting") -or ($b -match "Copying")) -and (!$end)){
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
                    if($b -match "Ok") { $end = $true }
                }
            }
        }
    }

    if($public){
        if($enable){
            $a = PsExec.exe /accepteula /nobanner \\$cn netsh advfirewall set Publicprofile state on 2>$null
            $end = $false
            $a | ForEach-Object {
                if($_) { $b = $_} else { $b = " "}
                if(!(($b -match "Connecting") -or ($b -match "Starting") -or ($b -match "Copying")) -and (!$end)){
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
                    if($b -match "Ok") { $end = $true }
                }
            }
        } else {
            $a = PsExec.exe /accepteula /nobanner \\$cn netsh advfirewall set Publicprofile state off 2>$null
            $end = $false
            $a | ForEach-Object {
                if($_) { $b = $_} else { $b = " "}
                if(!(($b -match "Connecting") -or ($b -match "Starting") -or ($b -match "Copying")) -and (!$end)){
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
                    if($b -match "Ok") { $end = $true }
                }
            }
        }
    }

    if($private){
        if($enable){
            $a = PsExec.exe /accepteula /nobanner \\$cn netsh advfirewall set Privateprofile state on 2>$null
            $end = $false
            $a | ForEach-Object {
                if($_) { $b = $_} else { $b = " "}
                if(!(($b -match "Connecting") -or ($b -match "Starting") -or ($b -match "Copying")) -and (!$end)){
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
                    if($b -match "Ok") { $end = $true }
                }
            }
        } else {
            $a = PsExec.exe /accepteula /nobanner \\$cn netsh advfirewall set Privateprofile state off 2>$null
            $end = $false
            $a | ForEach-Object {
                if($_) { $b = $_} else { $b = " "}
                if(!(($b -match "Connecting") -or ($b -match "Starting") -or ($b -match "Copying")) -and (!$end)){
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
                    if($b -match "Ok") { $end = $true }
                }
            }
        }
    }

    $a = PsExec.exe /accepteula /nobanner \\$cn netsh -c advfirewall show AllProfile 2>$null
    $end = $false
    $a | ForEach-Object {
        if($_){
            if($_) { $b = $_} else { $b = " "}
            if(!(($b -match "Connecting") -or ($b -match "Starting") -or ($b -match "Copying")) -and (!$end)){
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
                if($b -match "Ok") { $end = $true }
            }
        }
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "a" 2>$null
    Remove-Variable -Name "b" 2>$null
    Remove-Variable -Name "end" 2>$null

    $syncHash.control.Firewall_scriptblock_completed = $true
}

# Enable firewall with psexec
$syncHash.GUI.btn_fe3.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$domain  = $False
    [bool]$public  = $False
    [bool]$private = $False

    if(!($syncHash.GUI.cb_fDomain.isChecked) -and !($syncHash.GUI.cb_fPublic.isChecked) -and !($syncHash.GUI.cb_fPrivate.isChecked)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No profile selected" -NewLine $true
        return
    }
    
    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0091"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if($syncHash.GUI.cb_fDomain.isChecked) {
        $domain = $true
    } else {
        $domain = $False
    }
    if($syncHash.GUI.cb_fPublic.isChecked) {
        $public = $true
    } else {
        $public = $False
    }
    if($syncHash.GUI.cb_fPrivate.isChecked) {
        $private = $true
    } else {
        $private = $False
    }

    # Disable wedgets
    $syncHash.Gui.btn_fe1.IsEnabled   = $False
    $syncHash.Gui.btn_fe2.IsEnabled   = $False
    $syncHash.Gui.btn_fe3.IsEnabled   = $False
    $syncHash.Gui.btn_fd1.IsEnabled   = $False
    $syncHash.Gui.btn_fd2.IsEnabled   = $False
    $syncHash.Gui.btn_fd3.IsEnabled   = $False
    $syncHash.Gui.btn_fc1.IsEnabled   = $False
    $syncHash.Gui.btn_fc2.IsEnabled   = $False
    $syncHash.Gui.btn_fc3.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.FirewallPsExec_scriptblock).AddArgument($cn).AddArgument($domain).AddArgument($public).AddArgument($private).AddArgument($true)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Disable firewall with psexec
$syncHash.GUI.btn_fd3.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$domain  = $False
    [bool]$public  = $False
    [bool]$private = $False

    if(!($syncHash.GUI.cb_fDomain.isChecked) -and !($syncHash.GUI.cb_fPublic.isChecked) -and !($syncHash.GUI.cb_fPrivate.isChecked)) {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No profile selected" -NewLine $true
        return
    }
    
    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0092]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if($syncHash.GUI.cb_fDomain.isChecked) {
        $domain = $true
    } else {
        $domain = $False
    }
    if($syncHash.GUI.cb_fPublic.isChecked) {
        $public = $true
    } else {
        $public = $False
    }
    if($syncHash.GUI.cb_fPrivate.isChecked) {
        $private = $true
    } else {
        $private = $False
    }

    # Disable wedgets
    $syncHash.Gui.btn_fe1.IsEnabled   = $False
    $syncHash.Gui.btn_fe2.IsEnabled   = $False
    $syncHash.Gui.btn_fe3.IsEnabled   = $False
    $syncHash.Gui.btn_fd1.IsEnabled   = $False
    $syncHash.Gui.btn_fd2.IsEnabled   = $False
    $syncHash.Gui.btn_fd3.IsEnabled   = $False
    $syncHash.Gui.btn_fc1.IsEnabled   = $False
    $syncHash.Gui.btn_fc2.IsEnabled   = $False
    $syncHash.Gui.btn_fc3.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.FirewallPsExec_scriptblock).AddArgument($cn).AddArgument($domain).AddArgument($public).AddArgument($private).AddArgument($false)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Check firwall all methords ( The thread worker )
$syncHash.FirewallCheck_scriptblock = {
    param(
        [string]$cn,
        [int]$way,
        [pscredential]$cre
    )

    function fc1 {
        param(
            [string]$cn
        )

        $a = netsh -r $cn -c advfirewall show allprofile
        if(!($a)) {
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","Netsh is off.",$true
            Remove-Variable -Name "a" 2>$null
            return
        }
        $a | ForEach-Object {
            if($_) { $b = $_} else { $b = " "}
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
        }
        Remove-Variable -Name "a" 2>$null
        Remove-Variable -Name "b" 2>$null
    }

    function fc2 {
        param(
            [string]$cn,
            [pscredential]$cred
        )

        if($cred){
            $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock {Get-NetFirewallProfile}
        } else {
            $a = Invoke-Command -ComputerName $cn -ScriptBlock {Get-NetFirewallProfile}
        }
        if(!($a)) {
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","PSRemoting is off.",$true
            Remove-Variable -Name "a" 2>$null
            return
        }
        $a | ForEach-Object {
            if($_){
                $name = $_.Name.PadRight(7,' ')
                $msg = "$name : "
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$False
                if($_.enabled){
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","On",$true
                }else{
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","Off",$true
                }
            }
        }
        Remove-Variable -Name "a" 2>$null
        Remove-Variable -Name "name" 2>$null
        Remove-Variable -Name "msg" 2>$null
        Remove-Variable -Name "status" 2>$null
    }

    function fc3 {
        param(
            [string]$cn
        )

        [bool]$end = $false

        $a = PsExec.exe /accepteula /nobanner \\$cn netsh advfirewall show allprofile 2>$null
        if(!($a)) {
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","File sharing is off.",$true
            Remove-Variable -Name "a" 2>$null
            return
        }
        $a | ForEach-Object {
            if($_) { $b = $_.trim()} else { $b = " "}
            if(!(($b -match "Connecting") -or ($b -match "Starting") -or ($b -match "Copying")) -and (!$end)){
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
                if($b -match "Ok") { $end = $true }
            }
        }
        Remove-Variable -Name "a" 2>$null
        Remove-Variable -Name "b" 2>$null
        Remove-Variable -Name "end" 2>$null
    }

    switch ($way)
    {
        1  {fc1($cn)}
        2  {fc2 -cn $cn -cred $cre}
        3  {fc3($cn)}
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    $syncHash.control.Firewall_scriptblock_completed = $true
}

# Check firewall with netsh
$syncHash.GUI.btn_fc1.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    
    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0093]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_fe1.IsEnabled   = $False
    $syncHash.Gui.btn_fe2.IsEnabled   = $False
    $syncHash.Gui.btn_fe3.IsEnabled   = $False
    $syncHash.Gui.btn_fd1.IsEnabled   = $False
    $syncHash.Gui.btn_fd2.IsEnabled   = $False
    $syncHash.Gui.btn_fd3.IsEnabled   = $False
    $syncHash.Gui.btn_fc1.IsEnabled   = $False
    $syncHash.Gui.btn_fc2.IsEnabled   = $False
    $syncHash.Gui.btn_fc3.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.FirewallCheck_scriptblock).AddArgument($cn).AddArgument(1).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

#Check firewall with Powershell
$syncHash.GUI.btn_fc2.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    
    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0094]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_fe1.IsEnabled   = $False
    $syncHash.Gui.btn_fe2.IsEnabled   = $False
    $syncHash.Gui.btn_fe3.IsEnabled   = $False
    $syncHash.Gui.btn_fd1.IsEnabled   = $False
    $syncHash.Gui.btn_fd2.IsEnabled   = $False
    $syncHash.Gui.btn_fd3.IsEnabled   = $False
    $syncHash.Gui.btn_fc1.IsEnabled   = $False
    $syncHash.Gui.btn_fc2.IsEnabled   = $False
    $syncHash.Gui.btn_fc3.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.FirewallCheck_scriptblock).AddArgument($cn).AddArgument(2).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

#Check firewall with psexec
$syncHash.GUI.btn_fc3.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    
    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0095]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }
    
    # Disable wedgets
    $syncHash.Gui.btn_fe1.IsEnabled   = $False
    $syncHash.Gui.btn_fe2.IsEnabled   = $False
    $syncHash.Gui.btn_fe3.IsEnabled   = $False
    $syncHash.Gui.btn_fd1.IsEnabled   = $False
    $syncHash.Gui.btn_fd2.IsEnabled   = $False
    $syncHash.Gui.btn_fd3.IsEnabled   = $False
    $syncHash.Gui.btn_fc1.IsEnabled   = $False
    $syncHash.Gui.btn_fc2.IsEnabled   = $False
    $syncHash.Gui.btn_fc3.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.FirewallCheck_scriptblock).AddArgument($cn).AddArgument(3).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.sccmStatus_scriptblock = {
    param(
        [string]$cn,
        [pscredential]$cred
    )

    $msg = "SCCM Remote Control Service on $cn :"
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Orange",$msg,$true

    $msg = "=========================================================================================="
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$msg,$true

    $msg = " Access Level                                    = "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Access Level' }
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Access Level' }
    }
    if($a){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$a.tostring(),$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","N/A",$true
    }

    $msg = " Allow Client Change                             = "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Allow Client Change' }
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Allow Client Change' }
    }
    if($a){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$a.tostring(),$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","N/A",$true
    }

    $msg = " Allow Local Administrators to do Remote Control = "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Allow Local Administrators to do Remote Control' }
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Allow Local Administrators to do Remote Control' }
    }
    if($a){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$a.tostring(),$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","N/A",$true
    }

    $msg = " Allow Remote Control of an unattended computer  = "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Allow Remote Control of an unattended computer' }
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Allow Remote Control of an unattended computer' }
    }
    if($a){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$a.tostring(),$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","N/A",$true
    }

    $msg = " Audible Signal                                  = "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Audible Signal' }
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Audible Signal' }
    }
    if($a){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$a.tostring(),$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","N/A",$true
    }

    $msg = " Blocked Input                                   = "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'BlockedInput' }
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'BlockedInput' }
    }
    if($a){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$a.tostring(),$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","N/A",$true
    }

    $msg = " Enabled                                         = "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Enabled' }
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Enabled' }
    }
    if($a){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$a.tostring(),$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","N/A",$true
    }

    $msg = " Firewall Exception Profiles                     = "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Firewall Exception Profiles' }
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Firewall Exception Profiles' }
    }
    if($a){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$a.tostring(),$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","N/A",$true
    }

    $msg = " Permission Required                             = "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Permission Required' }
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Permission Required' }
    }
    if($a){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$a.tostring(),$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","N/A",$true
    }

    $msg = " Permitted Viewers                               = "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'PermittedViewers' }
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'PermittedViewers' }
    }
    if($a){
        [int]$i = 0
        $a | ForEach-Object {
            $i = $i + 1
            if($_){
                if($i -eq 1){
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$_,$true
                } else {
                    $msg = "                                                   $_"
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
                }
            }
        }
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","N/A",$true
    }

    $msg = " Remote Control Connection Bar                   = "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'RemCtrl Connection Bar' }
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'RemCtrl Connection Bar' }
    }
    if($a){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$a.tostring(),$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","N/A",$true
    }

    $msg = " Remote Control Task Bar Icon                    = "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'RemCtrl Taskbar Icon' }
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'RemCtrl Taskbar Icon' }
    }
    if($a){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$a.tostring(),$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","N/A",$true
    }

    $msg     = " Remote Control Security Group SID               = "
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$false

    if($cred){
        $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Remote Control Security Group SID' }
    } else {
        $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control' -Name 'Remote Control Security Group SID' }
    }
    if($a){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$a.tostring(),$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","N/A",$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow"," ...",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Service Status:",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow"," ",$true

    if($cred){
        $list = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { 
            $list = get-service -Name "CmRcService" | Out-String
            $list
        }
    } else {
        $list = Invoke-Command -ComputerName $cn -ScriptBlock { 
            $list = get-service -Name "CmRcService" | Out-String
            $list
        }
    }
    if($list){
        $a = $list.Split("`n")
        [int]$i = 0
        $a | ForEach-Object {
            $i++
            $b = $_.Trim()
            if($b) {
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$b,$true
            }
        }
    } else {
        $msg = "Service CmRcService not found."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
    }

    $msg = "=========================================================================================="
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$msg,$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "a" 2>$null
    Remove-Variable -Name "b" 2>$null
    Remove-Variable -Name "i" 2>$null
    Remove-Variable -Name "list" 2>$null
    Remove-Variable -Name "msg" 2>$null

    $syncHash.control.sccm_scriptblock_completed = $true
}

#Check SCCM remote service
$syncHash.GUI.btn_sccmStatus.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    
    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0096]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }
    
    # Disable wedgets
    $syncHash.Gui.btn_sccmUpdate.IsEnabled   = $False
    $syncHash.Gui.btn_sccmStatus.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.sccmStatus_scriptblock).AddArgument($cn).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})


$syncHash.sccmUpdate_scriptblock = {
    param(
        [string]$cn,
        [bool]$enable,
        [bool]$greenbar,
        [bool]$permission,
        [pscredential]$cred
    )

    if($enable){
        if($cred){
            Invoke-Command -ComputerName $cn -Credential $cred {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "Enabled" -Value 1}
        } else {
            Invoke-Command -ComputerName $cn {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "Enabled" -Value 1}
        }
        
    } else {
        if($cred){
            Invoke-Command -ComputerName $cn -Credential $cred {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "Enabled" -Value 0}
        } else {
            Invoke-Command -ComputerName $cn {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "Enabled" -Value 0}
        }
    }

    if($greenbar){
        if($cred){
            Invoke-Command -ComputerName $cn -Credential $cred {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "RemCtrl Connection Bar" -Value 1}
        } else {
            Invoke-Command -ComputerName $cn {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "RemCtrl Connection Bar" -Value 1}
        }
    } else {
        if($cred){
            Invoke-Command -ComputerName $cn -Credential $cred {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "RemCtrl Connection Bar" -Value 0}
        } else {
            Invoke-Command -ComputerName $cn {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "RemCtrl Connection Bar" -Value 0}
        }
    }

    if($permission){
        if($cred){
            Invoke-Command -ComputerName $cn -Credential $cred {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "Permission Required" -Value 1}
        } else {
            Invoke-Command -ComputerName $cn {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "Permission Required" -Value 1}
        }
    } else {
        if($cred){
            Invoke-Command -ComputerName $cn -Credential $cred {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "Permission Required" -Value 0}
        } else {
            Invoke-Command -ComputerName $cn {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "Permission Required" -Value 0}
        }
    }

    if($cred){
        Invoke-Command -ComputerName $cn -Credential $cred {Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\ConfigMgr10\Remote Control" -Name "UseAllMonitors" -Value 1}
    } else {
        Invoke-Command -ComputerName $cn {Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\ConfigMgr10\Remote Control" -Name "UseAllMonitors" -Value 1}
    }

    $msg = "Registry updated."
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$msg,$true

    $service = get-service -ComputerName $cn -Name "CmRcService"
    if($enable){
        Restart-Service -InputObject $service
    } else {
        Stop-Service -InputObject $service
    }
    
    if($cred){
        $tmp = Invoke-Command -ComputerName $cn -Credential $cred {
            $service = get-service -Name "CmRcService"
            $tmp = ($service.status).tostring()
            $tmp
        }
    } else {
        $tmp = Invoke-Command -ComputerName $cn {
            $service = get-service -Name "CmRcService"
            $tmp = ($service.status).tostring()
            $tmp
        }
    }
    if($tmp -match "Stopped"){
        $msg = "CmRcService is stopped"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
    } else {
        $msg = "CmRcService is running"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$msg,$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "msg" 2>$null
    Remove-Variable -Name "service" 2>$null
    Remove-Variable -Name "tmp" 2>$null

    $syncHash.control.sccm_scriptblock_completed = $true
}

# SCCM remote service update
$syncHash.GUI.btn_sccmUpdate.Add_Click({
    [string]$cn       = $syncHash.Gui.cb_Target.text
    [bool]$enable     = $syncHash.GUI.cb_sccmEnable.IsChecked
    [bool]$greenbar   = $syncHash.GUI.cb_sccmGreenBar.IsChecked
    [bool]$permission = $syncHash.GUI.cb_sccmPermission.IsChecked
    
    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0097]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }
    
    # Disable wedgets
    $syncHash.Gui.btn_sccmUpdate.IsEnabled   = $False
    $syncHash.Gui.btn_sccmStatus.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.sccmUpdate_scriptblock).AddArgument($cn).AddArgument($enable).AddArgument($greenbar).AddArgument($permission).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GetBitLockerKey_scriptblock = {
    param(
        [string]$cn
    )

    $objComputer = Get-ADComputer $cn
    $Bitlocker_Object = Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $objComputer.DistinguishedName -Properties 'msFVE-RecoveryPassword'
    [int]$i = 0
    if($Bitlocker_Object){
        if($Bitlocker_Object.count -eq 0) {
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","Nothing found.",$true
            $syncHash.control.GetBitLockerKey_scriptblock_completed = $true
            return
        }
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","28","LightGreen","Computer Name: $cn",$true
        $Bitlocker_Object | ForEach-Object {
            if($_){
                $i = $i + 1
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","ADObject $i :",$true
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen","Key ID       = ",$false
                $a = $_.Name
                $b = $a.Split('{')
                $c = $b[1].split('}')
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$c[0],$true
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen","Recovery Key = ",$false
                $c = $_.'msFVE-RecoveryPassword'
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$c,$true
                Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text $c -NewLine $true
            }
        }
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","Nothing found.",$true
        $syncHash.control.GetBitLockerKey_scriptblock_completed = $true
        return
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black","    ",$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "objComputer" 2>$null
    Remove-Variable -Name "Bitlocker_Object" 2>$null
    Remove-Variable -Name "i" 2>$null
    Remove-Variable -Name "a" 2>$null
    Remove-Variable -Name "b" 2>$null
    Remove-Variable -Name "c" 2>$null

    $syncHash.control.GetBitLockerKey_scriptblock_completed = $true
}

#Get BitLocker recovery key from AD
$syncHash.GUI.btn_BLKey.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_BLKey.IsEnabled = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.GetBitLockerKey_scriptblock).AddArgument($cn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# TCP Port input validation
$syncHash.Gui.tb_reboots.Add_TextChanged({
    if ($this.Text -match '[^0-9]') {
        $cursorPos = $this.SelectionStart
        $this.Text = $this.Text -replace '[^0-9]',''
        # move the cursor to the end of the text:
        # $this.SelectionStart = $this.Text.Length

        # or leave the cursor where it was before the replace
        $this.SelectionStart = $cursorPos - 1
        $this.SelectionLength = 0
    }
})

$syncHash.SuspendBitlocker_scriptblock = {
    param(
        [string]$cn, # Computer Name
        [int]$Count, # Boot Count
        [pscredential]$cred # Credential
    )

    if ($cred) {
        Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { 
            param(
                [int]$C
            )
            Suspend-BitLocker -MountPoint "C:" -RebootCount $C
        } -ArgumentList $Count
    } else {
        Invoke-Command -ComputerName $cn -ScriptBlock { 
            param(
                [int]$C
            )
            Suspend-BitLocker -MountPoint "C:" -RebootCount $C
        } -ArgumentList $Count
    }
    
    if ($cred) {
        $t = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock {Get-BitLockerVolume}
    } else {
        $t = Invoke-Command -ComputerName $cn -ScriptBlock {Get-BitLockerVolume}
    }
    $t | Out-GridView -Title "BitLocker enabled volume(s) on $cn"

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "t" 2>$null

    $syncHash.control.SuspendBitlocker_scriptblock_completed = $true
}

# Suspend the BitLocker
$syncHash.GUI.btn_BLSuspend.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($syncHash.Gui.tb_reboots.text)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Reboot count is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0098]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    [int]$Count = ($syncHash.Gui.tb_reboots.text) -as [int]

    # Disable wedgets
    $syncHash.Gui.btn_BLSuspend.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.SuspendBitlocker_scriptblock).AddArgument($cn).AddArgument($Count).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GUI.btn_ClearLog.Add_Click({
    Clear-Content $syncHash.LOG_PATH 2>$null
})

$syncHash.GUI.btn_ShowLog.Add_Click({
    $t = Get-Content -Path $syncHash.LOG_PATH 2>$null
    if($t){
        $t | ForEach-Object {
            Show-Result -Font "Courier New" -Size "18" -Color "White" -Text $_ -NewLine $true
        }
    }
})

$handler_keypress_LogButtons = {
    [string]$key = ($_.key).ToString()
    if($key -match "Escape"){
        $syncHash.Gui.rtb_Output.Document.Blocks.Clear()
    }
}
$syncHash.Window.add_KeyDown($handler_keypress_LogButtons)

$syncHash.UAC_scriptblock = {
    param(
        [string]$cn,
        [bool]$enable,
        [pscredential]$cred
    )

    $work = {
        param(
            [bool]$enable
        )

        [string]$e = ""
        [string]$ee = ""
        [string]$eee = ""
        [string]$eeee = ""

        if($enable) {
            $e = "2"
            $ee = "1"
            $eee = "1"
            $eeee = "0"
        } else {
            $e = "0"
            $ee = "0"
            $eee = "0"
            $eeee = "1"
        }

        $numVersion = (Get-CimInstance Win32_OperatingSystem).Version
        $numSplit = $numVersion.split(".")[0]
 
        if ($numSplit -eq 10) {
            try{
                Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value $e
                Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value $ee
                Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value $eee
                Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableUIADesktopToggle" -Value $eeee
            } catch {
                $e = "[Error 0099]"
                Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
                Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            }
        } Else {
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","This feature can only work on Windows 10.",$true
        }

        Remove-Variable -Name "e" 2>$null
        Remove-Variable -Name "ee" 2>$null
        Remove-Variable -Name "eee" 2>$null
        Remove-Variable -Name "eeee" 2>$null
        Remove-Variable -Name "numVersion" 2>$null
        Remove-Variable -Name "numSplit" 2>$null
        Remove-Variable -Name "enumSplit" 2>$null
    }

    if($cred){
        Invoke-Command -ComputerName $cn -Credential $cred $work -ArgumentList $enable
    } else {
        Invoke-Command -ComputerName $cn $work -ArgumentList $enable
    }

    if($enable){
        $msg = "UAC on $cn has been enabled."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$true
    } else {
        $msg = "UAC on $cn has been disabled."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "work" 2>$null
    Remove-Variable -Name "msg" 2>$null

    $syncHash.control.UAC_scriptblock_completed = $true
}

$syncHash.GUI.btn_UACEnable.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0100]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_UACEnable.IsEnabled  = $False
    $syncHash.Gui.btn_UACDisable.IsEnabled = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.UAC_scriptblock).AddArgument($cn).AddArgument($true).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GUI.btn_UACDisable.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0101]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_UACEnable.IsEnabled  = $False
    $syncHash.Gui.btn_UACDisable.IsEnabled = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.UAC_scriptblock).AddArgument($cn).AddArgument($false).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.who_scriptblock = {
    param(
        [string]$cn
    )

    [string]$msgwho  = ""
    [string]$msgwho1 = ""

    try{
        $aw = query user /server:$cn 2>$null
    } catch {
        $e = "[Error 0102]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }

    $msgwho = "Logon user report on $cn :"
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","22","Yellow",$msgwho,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Report 1:",$true
    
    if($aw){
        $bw = ((($aw) -replace '^>', '') -replace '\s{2,}', ',').Trim() | ForEach-Object {
            if ($_.Split(',').Count -eq 5) {
                Write-Output ($_ -replace '(^[^,]+)', '$1,')
            } else {
                Write-Output $_
            }
        }
        $cw = $bw[0].split(',')
        $msgwho1 = $cw[0].PadRight(20, ' ') + $cw[1].PadRight(20, ' ') + $cw[2].PadRight(5, ' ') + $cw[3].PadRight(10, ' ') + $cw[4].PadRight(20, ' ') + $cw[5].PadRight(20, ' ')
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msgwho1,$true
        $cw = $bw[1].split(',')
        $msgwho1 = $cw[0].PadRight(20, ' ') + $cw[1].PadRight(20, ' ') + $cw[2].PadRight(5, ' ') + $cw[3].PadRight(10, ' ') + $cw[4].PadRight(20, ' ') + $cw[5].PadRight(20, ' ')
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msgwho1,$true
    } else {
        $msgwho1 = "  No logon user at this moment."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Orange",$msgwho1,$true
    }

    $aa = PsLoggedon64.exe /nobanner /accepteula \\$cn
    if($aa){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Report 2:",$true
        for([int]$ii=2;$ii -lt ($aa.length);$ii++){
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$aa[$ii],$true
        }
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "aw" 2>$null
    Remove-Variable -Name "e" 2>$null
    Remove-Variable -Name "msgwho" 2>$null
    Remove-Variable -Name "bw" 2>$null
    Remove-Variable -Name "cw" 2>$null
    Remove-Variable -Name "msgwho1" 2>$null
    Remove-Variable -Name "aa" 2>$null
    Remove-Variable -Name "ii" 2>$null

    $syncHash.control.Who_scriptblock_completed = $true
}

# Show logon user
$syncHash.Gui.btn_Who.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0103]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_Who.IsEnabled = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.who_scriptblock).AddArgument($cn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.ListProfile_scriptblock = {
    param(
        [string]$cn
    )

    try{
        $ups = Get-WmiObject -Class Win32_UserProfile -ComputerName $cn
        $msg = "Profile list on $cn :"
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
        [int]$count = 0
        if($ups){
            $ups | ForEach-Object {
                if(!(($_.LocalPath -match "NetworkService") -or ($_.LocalPath -match "LocalService") -or $_.LocalPath -match "systemprofile")){
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$_.LocalPath,$true
                    $count++
                }
            }
            $msg = "$count profile(s) found in the Registry."
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",$msg,$true
        } else {
            $e = "[Error 0104]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        }
    } catch {
        $e = "[Error 0105]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "ups" 2>$null
    Remove-Variable -Name "count" 2>$null
    Remove-Variable -Name "msg" 2>$null
    Remove-Variable -Name "e" 2>$null

    $syncHash.control.DeleteProfile_Scriptblock_completed = $true
}

$syncHash.GUI.btn_UPList.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0106]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # Disable wedgets
    $syncHash.Gui.btn_UPAdd.IsEnabled   = $False
    $syncHash.Gui.btn_UPDelete.IsEnabled   = $False
    $syncHash.Gui.btn_UPList.IsEnabled   = $False
    $syncHash.Gui.btn_UPClear.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.ListProfile_Scriptblock).AddArgument($cn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GUI.btn_UPAdd.Add_Click({
    [string]$ac = $syncHash.Gui.TB_Account.text

    if($ac) {
        if(!($syncHash.Gui.lb_pList.items.Contains($ac))){
            $syncHash.Gui.lb_pList.items.add($ac)
            $syncHash.Gui.TB_Account.text = ""
        }
    } else {
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text " Please provide an account name." -NewLine $true
    }
})

$syncHash.GUI.btn_UPClear.Add_Click({
    $syncHash.GUI.lb_pList.Items.Clear()
})

$syncHash.DeleteProfile_Scriptblock = {
    param(
        [string]$cn,
        [System.Windows.Controls.ItemCollection]$accounts
    )

    try{
        $ups = Get-WmiObject -Class Win32_UserProfile -ComputerName $cn
    } catch {
        $e = "[Error 0107]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        $syncHash.control.DeleteProfile_Scriptblock_completed = $true
        return
    }

    $accounts | ForEach-Object {
        $ac = $_
        if($ups){
            $ups | ForEach-Object {
                if($_.LocalPath -eq "C:\Users\$ac") {
                    $_ | Remove-WmiObject
                    $msg = "$ac has been removed from $cn"
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","LightGreen",$msg,$true
                }
            }
        } else {
            $e = "[Error 0108]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            $syncHash.control.DeleteProfile_Scriptblock_completed = $true
            return
        }
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "ups" 2>$null
    Remove-Variable -Name "e" 2>$null
    Remove-Variable -Name "ac" 2>$null
    Remove-Variable -Name "msg" 2>$null

    $syncHash.control.DeleteProfile_Scriptblock_completed = $true
}

$syncHash.GUI.btn_UPDelete.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if($syncHash.Gui.lb_pList.Items.Count -eq 0){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Profile list is empty." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0109]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # Disable wedgets
    $syncHash.Gui.btn_UPAdd.IsEnabled   = $False
    $syncHash.Gui.btn_UPDelete.IsEnabled   = $False
    $syncHash.Gui.btn_UPList.IsEnabled   = $False
    $syncHash.Gui.btn_UPClear.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.DeleteProfile_Scriptblock).AddArgument($cn).AddArgument($syncHash.Gui.lb_pList.Items)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GUI.lb_pList.add_SelectionChanged({
    $syncHash.GUI.lb_pList.Items.remove($syncHash.GUI.lb_pList.SelectedItem)
})

$syncHash.GUI.lb_tList.add_SelectionChanged({
    $syncHash.GUI.lb_tList.Items.remove($syncHash.GUI.lb_tList.SelectedItem)
})

$syncHash.GUI.lb_UserList.add_SelectionChanged({
    $syncHash.GUI.lb_UserList.Items.remove($syncHash.GUI.lb_UserList.SelectedItem)
})

$syncHash.GetCPUProcess_scriptblock = {
    param(
        [string]$cn,
        [bool]$remote
    )
    $properties=@(
        @{Name="Name"; Expression = {$_.name}},
        @{Name="PID"; Expression = {$_.IDProcess}},
        @{Name="CPU (%)"; Expression = {$_.PercentProcessorTime}},
        @{Name="Memory (MB)"; Expression = {[Math]::Round(($_.workingSetPrivate / 1mb),2)}}
        @{Name="Disk (MB)"; Expression = {[Math]::Round(($_.IODataOperationsPersec / 1mb),2)}}
    )

    if($remote){
    $ProcessCPU = Get-WmiObject  -class Win32_PerfFormattedData_PerfProc_Process -ComputerName $cn |
        Select-Object $properties |
        Sort-Object "CPU (%)" -desc |
        Select-Object -First 10 |
        Format-Table -AutoSize
    } else {
        $ProcessCPU = Get-WmiObject  -class Win32_PerfFormattedData_PerfProc_Process |
        Select-Object $properties |
        Sort-Object "CPU (%)" -desc |
        Select-Object -First 10 |
        Format-Table -AutoSize
    }
    $a = $ProcessCPU | Out-String
    $b = $a.Split("`n")
    if($remote){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","22","Cyan","Top 10 processes on $cn",$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","22","Cyan","Top 10 processes on $env:COMPUTERNAME",$true
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true
    $b | ForEach-Object {
        if($_.length -le 1) {return}
        $msg = $_.trim()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$msg,$true
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -name "properties" 2>$null
    Remove-Variable -name "ProcessCPU" 2>$null
    Remove-Variable -name "a" 2>$null
    Remove-Variable -name "b" 2>$null
    Remove-Variable -name "msg" 2>$null
}

$syncHash.GUI.btn_SearchProc.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$p = $syncHash.Gui.tb_ProcessName.text
    [bool]$remote = $false
    [string]$msg = ""

    if([string]::IsNullOrEmpty($p)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Nothing to search." -NewLine $true
        return
    } 

    if([string]::IsNullOrEmpty($cn)){
        $cn = $env:COMPUTERNAME
        $remote = $false
    } else {
        $remote = $true
    }

    if($remote) {
        try{
            $a = Get-Process -ComputerName $cn -Name $p 2>$null | Out-String
        } catch {
            $e = "[Error 0110]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","22","Yellow","Failed. Possible reason: RemoteRegistry is disabled.",$true
        }
        if(!$a){
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","22","Yellow","Nothing found on $cn",$true
            return
        }
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","22","Cyan","Results from $cn",$true
    } else {
        $a = Get-Process -Name $p 2>$null | Out-String
        if(!$a){
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","22","Yellow","Nothing found on $env:COMPUTERNAME",$true
            return
        }
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","22","Cyan","Results from $env:COMPUTERNAME",$true
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true
    $b = $a.Split("`n")
    $b | ForEach-Object {
        if($_.length -le 1) {return}
        $msg = $_.trim()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$msg,$true
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -Name "cn" 2>$null
    Remove-Variable -Name "p" 2>$null
    Remove-Variable -Name "remote" 2>$null
    Remove-Variable -Name "msg" 2>$null
    Remove-Variable -Name "a" 2>$null
    Remove-Variable -Name "b" 2>$null
})

$syncHash.ListProc_Scriptblock = {
    param(
        [string]$cn,
        [bool]$remote
    )

    $properties=@(
        @{Name="Name"; Expression = {$_.name}},
        @{Name="PID"; Expression = {$_.IDProcess}},
        @{Name="CPU (%)"; Expression = {$_.PercentProcessorTime}},
        @{Name="Memory (MB)"; Expression = {[Math]::Round(($_.workingSetPrivate / 1mb),2)}}
        @{Name="Disk (MB)"; Expression = {[Math]::Round(($_.IODataOperationsPersec / 1mb),2)}}
    )

    if($remote){
    $ProcessCPU = Get-WmiObject  -class Win32_PerfFormattedData_PerfProc_Process -ComputerName $cn |
        Select-Object $properties |
        Sort-Object "CPU (%)" -desc |
        Select-Object -First 10 |
        Format-Table -AutoSize
    } else {
        $ProcessCPU = Get-WmiObject  -class Win32_PerfFormattedData_PerfProc_Process |
        Select-Object $properties |
        Sort-Object "CPU (%)" -desc |
        Select-Object -First 10 |
        Format-Table -AutoSize
    }
    $a = $ProcessCPU | Out-String
    $b = $a.Split("`n")
    if($remote){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","22","Cyan","Top 10 processes on $cn",$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","22","Cyan","Top 10 processes on $env:COMPUTERNAME",$true
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true
    $b | ForEach-Object {
        if($_.length -le 1) {return}
        $msg = $_.trim()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$msg,$true
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black"," ",$true

    Remove-Variable -name "properties" 2>$null
    Remove-Variable -name "ProcessCPU" 2>$null
    Remove-Variable -name "a" 2>$null
    Remove-Variable -name "b" 2>$null
    Remove-Variable -name "msg" 2>$null

    $syncHash.control.Process_scriptblock_completed = $true
}

$syncHash.GUI.btn_ListProc.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$remote = $false

    if([string]::IsNullOrEmpty($cn)){
        $cn = $env:COMPUTERNAME
        $remote = $false
    } else {
        $remote = $true
    }

    # Disable wedgets
    $syncHash.Gui.btn_SearchProc.IsEnabled   = $False
    $syncHash.Gui.btn_ListProc.IsEnabled   = $False
    $syncHash.Gui.btn_KillProc.IsEnabled   = $False
    $syncHash.Gui.btn_KillMore.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.ListProc_Scriptblock).AddArgument($cn).AddArgument($remote)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GUI.btn_KillProc.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$pName = $syncHash.Gui.tb_ProcessName.text
    $cred = $syncHash.PSRemote_credential

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No Targer." -NewLine $true
        return
    }
    if([string]::IsNullOrEmpty($pName)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Nothing to kill." -NewLine $true
        return
    } 

    try{
        if($cred){
            Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Stop-Process -Name $USING:pName -Force }
        } else {
            Invoke-Command -ComputerName $cn -ScriptBlock { Stop-Process -Name $USING:pName -Force }
        }
    } catch {
        $e = "[Error 0111] Failed to stop process."
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    Show-Result -Font "Courier New" -Size "18" -Color "LightGreen" -Text "  $Global:emoji_check Command sent." -NewLine $true
})

$syncHash.KillMore_Scriptblock = {
    [CmdletBinding()]
    param(
        [string]$cn
    )

    $cred = $syncHash.PSRemote_credential

    try{
        if($cred){
            Get-Process -ComputerName $cn | Out-GridView -PassThru | Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Stop-Process -Force }
        } else {
            Get-Process -ComputerName $cn | Out-GridView -PassThru | Invoke-Command -ComputerName $cn -ScriptBlock { Stop-Process -Force }
        }
    } catch {
        $e = "[Error 0112] Failed to stop process."
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }

    $syncHash.control.Process_scriptblock_completed = $true
}

$syncHash.GUI.btn_KillMore.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0113]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_SearchProc.IsEnabled = $False
    $syncHash.Gui.btn_ListProc.IsEnabled   = $False
    $syncHash.Gui.btn_KillProc.IsEnabled   = $False
    $syncHash.Gui.btn_KillMore.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.KillMore_Scriptblock).AddArgument($cn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GUI.btn_SendMsg.Add_Click({
    [string]$cn  = $syncHash.Gui.cb_Target.text

    [void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')

    $title = "Send alert to $cn"
    $msg   = 'Enter your message:'

    $text = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
    
    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand No target." -NewLine $true
        return
    } 

    if([string]::IsNullOrEmpty($msg)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Nothing to send." -NewLine $true
        return
    } 

    Start-Process -Filepath "psexec.exe" -Argumentlist "/accepteula /nobanner \\$cn msg.exe * /TIME:30 $text" -NoNewWindow

    Remove-Variable -Name "cn" 2>$null
    Remove-Variable -Name "msg" 2>$null
    Remove-Variable -Name "text" 2>$null
})

$syncHash.SearchApp_scriptblock = {
    param(
        [string]$cn,
        [string]$name
    )

    try{
        $p = Get-WmiObject -ComputerName $cn -Class Win32_Product | Select-Object Name,IdentifyingNumber | Where-Object -Property name -Match $name
    }catch{
        $e = "[Error 0114]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }

    if($p){
        $p | ForEach-Object {
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$_.Name,$false
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","     ",$false
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$_.IdentifyingNumber,$true
        }
    }else{
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","Nothing found.",$true
    }
    
    Remove-Variable -Name "cn" 2>$null
    Remove-Variable -Name "name" 2>$null
    Remove-Variable -Name "p" 2>$null
    $syncHash.control.Uninstall_scriptblock_completed = $true
}

$syncHash.Gui.btn_SearchApp.Add_click({
    [string]$cn  = $syncHash.Gui.cb_Target.text
    [string]$name = $syncHash.Gui.tb_appName.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0115]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_SearchApp.IsEnabled   = $False
    $syncHash.Gui.btn_Uninstall.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.SearchApp_Scriptblock).AddArgument($cn).AddArgument($name)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.Uninstall_scriptblock = {
    param(
        [string]$cn,
        [string]$id
    )

    try{
        $p = Get-WmiObject -ComputerName $cn -Class Win32_Product | Where-Object -Property IdentifyingNumber -Match $id
    }catch{
        $e = "[Error 0116]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
    }
    
    if($p){
        $p.uninstall()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","Uninstall completed.",$true
    }else{
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","Uninstall failed.",$true
    }

    Remove-Variable -Name "cn" 2>$null
    Remove-Variable -Name "id" 2>$null
    Remove-Variable -Name "p" 2>$null
    $syncHash.control.Uninstall_scriptblock_completed = $true
}

$syncHash.Gui.btn_Uninstall.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$id = $syncHash.Gui.tb_appName.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($id)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Program ID missing." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0117]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    $cn = $cn.Trim()
    $id = $id.Trim()

    # Disable wedgets
    $syncHash.Gui.btn_SearchApp.IsEnabled   = $False
    $syncHash.Gui.btn_Uninstall.IsEnabled   = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.Uninstall_Scriptblock).AddArgument($cn).AddArgument($id)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })
    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.Gui.btn_LocalWindow.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0118]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    Start-Process -FilePath cmd.exe -Verb Runas -ArgumentList "/k PsExec.exe /accepteula /nobanner \\$cn -s powershell.exe"
})

$syncHash.Gui.btn_RemoteWindow.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [int]$sid = 0

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($syncHash.Gui.tb_SessionID.text)){
        $sid = 0
    } else {
        $sid = [int]$syncHash.Gui.tb_SessionID.text
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0119]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    Start-Process -FilePath cmd.exe -Verb Runas -ArgumentList "/C PsExec.exe /accepteula /nobanner \\$cn -s -i $sid -d powershell.exe"
})

$syncHash.Gui.btn_LocalCMD.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0120]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    Start-Process -FilePath cmd.exe -Verb Runas -ArgumentList " /t:0a /k PsExec.exe /accepteula /nobanner \\$cn -s cmd"
})

$syncHash.Gui.btn_RemoteCMD.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [int]$sid = 0

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($syncHash.Gui.tb_SessionID.text)){
        $sid = 0
    } else {
        $sid = [int]$syncHash.Gui.tb_SessionID.text
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0121]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    Start-Process -FilePath cmd.exe -Verb Runas -ArgumentList "'/k PsExec.exe /accepteula /nobanner \\$cn -s -i $sid -d cmd /t:0a' & exit"
})

$syncHash.QuerySession_scriptblock = {
    param(
        [string]$cn
    )

    $a = PsExec64.exe -accepteula -nobanner \\$cn -c C:\Sysinternals\logonsessions64.exe -accepteula -nobanner -p

    if(!($a)) {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","File sharing is off.",$true
        Remove-Variable -Name "a" 2>$null
        return
    }
    Clear-Content "$env:TEMP\logon.txt"
    "Current logon sessions on $cn :" | Out-File  $env:TEMP\logon.txt
    $a | ForEach-Object {
        if($_) { $b = $_.trim()} else { $b = " "}
        if(!(($b -match "Connecting") -or ($b -match "Starting") -or ($b -match "Copying"))){
            #Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lim",$b,$true
            $b | Out-File  $env:TEMP\logon.txt -Append
        }
    }

    notepad.exe $env:TEMP\logon.txt

    $syncHash.Control.QuerySession_scriptblock_Completed = $true
}

$syncHash.Gui.btn_Session.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0122]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_Session.IsEnabled = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.QuerySession_scriptblock).AddArgument($cn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

# Session # input validation
$syncHash.Gui.tb_SessionID.Add_TextChanged({
    if ($this.Text -match '[^0-9]') {
        $cursorPos = $this.SelectionStart
        $this.Text = $this.Text -replace '[^0-9]',''
        # move the cursor to the end of the text:
        # $this.SelectionStart = $this.Text.Length

        # or leave the cursor where it was before the replace
        $this.SelectionStart = $cursorPos - 1
        $this.SelectionLength = 0
    }
})

$syncHash.network_scriptblock = {
    param(
        [string]$cn,
        [int]$option,
        [pscredential]$cred
    )

    if($cred){
        switch ($option) {
            1 { $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-NetAdapter | Select-Object -Property MacAddress,Status,LinkSpeed,PhysicalMediaType,MediaConnectionState,ifAlias,IfDesc,Name,FullDuplex,DriverProvider}; $a | Out-GridView -Title "Network adapters on $cn"; break }
            2 { $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { Get-NetIPAddress | Select-Object -Property IPAddress,PrefixLength,InterfaceAlias,AddressFamily,PrefixOrigin,SuffixOrigin }; $a | Out-GridView -Title "IP configuration on $cn"; break }
            3 { $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { ipconfig /all }
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","===============",$true
                for($i=0;$i -lt $a.Length; $i++){
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$a[$i],$true
                }
                break
            }
            4 { Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","===============",$true 
                $a=Test-NetConnection $cn -traceroute | Out-String
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$a.Trim(),$true
                break
            }
            Default {}
        }
    } else {
        switch ($option) {
            1 { $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-NetAdapter | Select-Object -Property MacAddress,Status,LinkSpeed,PhysicalMediaType,MediaConnectionState,ifAlias,IfDesc,Name,FullDuplex,DriverProvider}; $a | Out-GridView -Title "Network adapters on $cn" }
            2 { $a = Invoke-Command -ComputerName $cn -ScriptBlock { Get-NetIPAddress | Select-Object -Property IPAddress,PrefixLength,InterfaceAlias,AddressFamily,PrefixOrigin,SuffixOrigin }; $a | Out-GridView -Title "IP configuration on $cn" }
            3 { $a = Invoke-Command -ComputerName $cn -ScriptBlock { ipconfig /all }
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","===============",$true
                for($i=0;$i -lt $a.Length; $i++){
                    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$a[$i],$true
                }}
            4 { Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","===============",$true 
                $a=Test-NetConnection $cn -traceroute | Out-String
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$a.Trim(),$true
            }
            Default {}
        }
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black","     ",$true

    Remove-Variable -Name "a" 2>$null
    $syncHash.control.network_scriptblock_Connected = $true
}

$syncHash.GUI.btn_Adapters.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$remote = $false

    if([string]::IsNullOrEmpty($cn)){
        $remote = $false
    } else {
        # Ping test
        try {
            $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
        } catch {
            $e = "[Error 0123]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            return
        }

        if(!$test){
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
            return
        }
        $remote = $true
        if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
            $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
        }
    }

    if(!($remote)){
        Get-NetAdapter | Select-Object -Property MacAddress,Status,LinkSpeed,PhysicalMediaType,MediaConnectionState,ifAlias,IfDesc,Name,FullDuplex,DriverProvider | Out-GridView -Title "Network adapters on $env:COMPUTERNAME"
    } else {
        # Disable wedgets
        $syncHash.Gui.btn_Adapters.IsEnabled = $False
        $syncHash.Gui.btn_IPConf.IsEnabled   = $False
        $syncHash.Gui.btn_IPConfig.IsEnabled   = $False
        $syncHash.Gui.btn_Tracert.IsEnabled  = $False

        # create the extra Powershell session and add the script block to execute
        $Session = [PowerShell]::Create().AddScript($syncHash.network_scriptblock).AddArgument($cn).AddArgument(1).AddArgument($syncHash.PSRemote_credential)
        
        # execute the code in this session
        $Session.RunspacePool = $RunspacePool
        $Handle = $Session.BeginInvoke()
        $syncHash.Jobs.Add([PSCustomObject]@{
            'Session' = $Session
            'Handle' = $Handle
        })

        $syncHash.Gui.PB.IsIndeterminate = $true
    }
})

$syncHash.GUI.btn_IPConf.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$remote = $false

    if([string]::IsNullOrEmpty($cn)){
        $remote = $false
    } else {
        # Ping test
        try {
            $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
        } catch {
            $e = "[Error 0124]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            return
        }

        if(!$test){
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
            return
        }
        $remote = $true
        if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
            $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
        }
    }

    if(!($remote)){
        Get-NetIPAddress | Select-Object -Property IPAddress,PrefixLength,InterfaceAlias,AddressFamily,PrefixOrigin,SuffixOrigin | Out-GridView -Title "IP configuration on $env:COMPUTERNAME"
    } else {
        # Disable wedgets
        $syncHash.Gui.btn_Adapters.IsEnabled = $False
        $syncHash.Gui.btn_IPConf.IsEnabled   = $False
        $syncHash.Gui.btn_IPConfig.IsEnabled   = $False
        $syncHash.Gui.btn_Tracert.IsEnabled  = $False

        # create the extra Powershell session and add the script block to execute
        $Session = [PowerShell]::Create().AddScript($syncHash.network_scriptblock).AddArgument($cn).AddArgument(2).AddArgument($syncHash.PSRemote_credential)
        
        # execute the code in this session
        $Session.RunspacePool = $RunspacePool
        $Handle = $Session.BeginInvoke()
        $syncHash.Jobs.Add([PSCustomObject]@{
            'Session' = $Session
            'Handle' = $Handle
        })

        $syncHash.Gui.PB.IsIndeterminate = $true
    }
})

$syncHash.GUI.btn_IPConfig.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$remote = $false

    if([string]::IsNullOrEmpty($cn)){
        $remote = $false
    } else {
        # Ping test
        try {
            $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
        } catch {
            $e = "[Error 0125]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            return
        }

        if(!$test){
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
            return
        }
        $remote = $true
        if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
            $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
        }
    }

    if(!($remote)){
        $a = Invoke-Command -ScriptBlock { ipconfig /all }
        Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "=== IPConfig on local machine:" -NewLine $true
        for($i=0;$i -lt $a.Length; $i++){
            Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text $a[$i] -NewLine $true
        }
    } else {
        # Disable wedgets
        $syncHash.Gui.btn_Adapters.IsEnabled = $False
        $syncHash.Gui.btn_IPConf.IsEnabled   = $False
        $syncHash.Gui.btn_IPConfig.IsEnabled = $False
        $syncHash.Gui.btn_Tracert.IsEnabled  = $False

        # create the extra Powershell session and add the script block to execute
        $Session = [PowerShell]::Create().AddScript($syncHash.network_scriptblock).AddArgument($cn).AddArgument(3).AddArgument($syncHash.PSRemote_credential)
        
        # execute the code in this session
        $Session.RunspacePool = $RunspacePool
        $Handle = $Session.BeginInvoke()
        $syncHash.Jobs.Add([PSCustomObject]@{
            'Session' = $Session
            'Handle' = $Handle
        })

        $syncHash.Gui.PB.IsIndeterminate = $true
    }
})

$syncHash.Gui.btn_Tracert.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [bool]$remote = $false

    if([string]::IsNullOrEmpty($cn)){
        $remote = $false
    } else {
        # Ping test
        try {
            $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
        } catch {
            $e = "[Error 0126]"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            return
        }

        if(!$test){
            Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
            return
        }
        $remote = $true
        if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
            $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
        }
    }

    if($remote){
        # Disable wedgets
        $syncHash.Gui.btn_Adapters.IsEnabled = $False
        $syncHash.Gui.btn_IPConf.IsEnabled   = $False
        $syncHash.Gui.btn_IPConfig.IsEnabled = $False
        $syncHash.Gui.btn_Tracert.IsEnabled  = $False

        # create the extra Powershell session and add the script block to execute
        $Session = [PowerShell]::Create().AddScript($syncHash.network_scriptblock).AddArgument($cn).AddArgument(4)
        
        # execute the code in this session
        $Session.RunspacePool = $RunspacePool
        $Handle = $Session.BeginInvoke()
        $syncHash.Jobs.Add([PSCustomObject]@{
            'Session' = $Session
            'Handle' = $Handle
        })

        $syncHash.Gui.PB.IsIndeterminate = $true
    } else {
        Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "  $Global:emoji_Laugh You don't want to trace yourself" -NewLine $true
    }
})

########## BSOD Analyze ############
$syncHash.BSOD_scriptblock = {
    param(
        [string]$cn,
        [pscredential]$cred
    )

    $bsod = {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "https://www.nirsoft.net/utils/bluescreenview.zip" -OutFile "$($ENV:Temp)\bluescreeview.zip"
            Expand-Archive "$($env:Temp)\bluescreeview.zip" -DestinationPath "$($env:Temp)" -Force
            Start-Process -FilePath "$($env:Temp)\Bluescreenview.exe" -ArgumentList "/scomma `"$($env:Temp)\Export.csv`"" -Wait
        }
        catch {
            $e = "[Error 0127] Failed to run bluescreeview"
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
            Invoke-Command $syncHash.Log_scriptblock -ArgumentList $($_.Exception.Message)
            return
        }

        $BSODs = get-content "$($env:Temp)\Export.csv" | ConvertFrom-Csv -Delimiter ',' -Header Dumpfile, Timestamp, Reason, Errorcode, Parameter1, Parameter2, Parameter3, Parameter4, CausedByDriver | foreach-object { $_.Timestamp = [datetime]::Parse($_.timestamp, [System.Globalization.CultureInfo]::CurrentCulture); $_ }
        Remove-item "$($ENV:Temp)\Export.csv" -Force
        Remove-item "$($ENV:Temp)\readme.txt" -Force
        Remove-item "$($ENV:Temp)\bluescreeview.zip" -Force
        Remove-item "$($ENV:Temp)\BlueScreenView.chm" -Force
        Remove-item "$($ENV:Temp)\Bluescreenview.exe" -Force

        $BSODFilter = $BSODs #| where-object { $_.Timestamp -gt ((get-date).addhours(-24)) }

        if (!$BSODFilter) {
            "Congratulation! - No BSOD found"
        }
        else {
            $BSODFilter
        }

        Remove-Variable -Name "e" 2>$null
        Remove-Variable -Name "BSODs" 2>$null
        Remove-Variable -Name "BSODFilter" 2>$null
    }

    try{
        if($cred){
            $a = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock $bsod
        } else {
            $a = Invoke-Command -ComputerName $cn -ScriptBlock $bsod
        }
    } catch {
        $e = "[Error 0128] PSRemoting failed"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","22","Red","Failed, Possible reason: PSRemoting is not on.",$true
        Remove-Variable -Name "e" 2>$null
        return
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","22","Lime","BSOD report : $cn",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","22","Yellow","===========",$true

    if(($a.gettype()).Name -eq "String") {
        if($a){
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$a,$true
        }

    } elseif(($a.gettype()).Name -eq "Object[]") {
        for($i=0;$i -lt $a.Count; $i++) {
            $j = $i + 1
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Crash ($j)",$true
            if($a[$i].Dumpfile){
                $msg = "Dumpfile".PadRight(15, ' ') + ": " + $a[$i].Dumpfile
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true                
            }
            if($a[$i].Timestamp){
                $msg = "Timestamp".PadRight(15, ' ') + ": " + $a[$i].Timestamp
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a[$i].Reason){
                $msg = "Reason".PadRight(15, ' ') + ": " + $a[$i].Reason
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a[$i].Errorcode){
                $msg = "Errorcode".PadRight(15, ' ') + ": " + $a[$i].Errorcode
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a[$i].Parameter1){
                $msg = "Parameter1".PadRight(15, ' ') + ": " + $a[$i].Parameter1
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a[$i].Parameter2){
                $msg = "Parameter2".PadRight(15, ' ') + ": " + $a[$i].Parameter2
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a[$i].Parameter3){
                $msg = "Parameter3".PadRight(15, ' ') + ": " + $a[$i].Parameter3
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a[$i].Parameter4){
                $msg = "Parameter4".PadRight(15, ' ') + ": " + $a[$i].Parameter4
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a[$i].CausedByDriver){
                $msg = "CausedByDriver".PadRight(15, ' ') + ": " + $a[$i].CausedByDriver
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a[$i].PSComputerName){
                $msg = "PSComputerName".PadRight(15, ' ') + ": " + $a[$i].PSComputerName
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a[$i].RunspaceId){
                $msg = "RunspaceId".PadRight(15, ' ') + ": " + $a[$i].RunspaceId
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black","     ",$true
        }
        Remove-Variable -Name "i" 2>$null
        Remove-Variable -Name "j" 2>$null
    } else {
        if($a){
            if($a.Dumpfile){
                $msg = "Dumpfile".PadRight(15, ' ') + ": " + $a.Dumpfile
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a.Timestamp){
                $msg = "Timestamp".PadRight(15, ' ') + ": " + $a.Timestamp
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a.Reason){
                $msg = "Reason".PadRight(15, ' ') + ": " + $a.Reason
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a.Errorcode){
                $msg = "Errorcode".PadRight(15, ' ') + ": " + $a.Errorcode
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a.Parameter1){
                $msg = "Parameter1".PadRight(15, ' ') + ": " + $a.Parameter1
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a.Parameter2){
                $msg = "Parameter2".PadRight(15, ' ') + ": " + $a.Parameter2
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a.Parameter3){
                $msg = "Parameter3".PadRight(15, ' ') + ": " + $a.Parameter3
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a.Parameter4){
                $msg = "Parameter4".PadRight(15, ' ') + ": " + $a.Parameter4
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a.CausedByDriver){
                $msg = "CausedByDriver".PadRight(15, ' ') + ": " + $a.CausedByDriver
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a.PSComputerName){
                $msg = "PSComputerName".PadRight(15, ' ') + ": " + $a.PSComputerName
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
            if($a.RunspaceId){
                $msg = "RunspaceId".PadRight(15, ' ') + ": " + $a.RunspaceId
                Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$msg,$true
            }
        }
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Black","     ",$true
    Remove-Variable -Name "a" 2>$null
    Remove-Variable -Name "msg" 2>$null
    $syncHash.Control.BSOD_scriptblock_Connected = $true
}

$syncHash.Gui.btn_Analyze.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0129]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        Remove-Variable -Name "e" 2>$null
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if(!($syncHash.Gui.cb_Target.items.Contains($syncHash.Gui.cb_Target.Text))){
        $syncHash.Gui.cb_Target.items.add($syncHash.Gui.cb_Target.Text)
    }

    # Disable wedgets
    $syncHash.Gui.btn_Analyze.IsEnabled = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.BSOD_scriptblock).AddArgument($cn).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true

    Remove-Variable -Name "test" 2>$null
    Remove-Variable -Name "cn" 2>$null
    Remove-Variable -Name "session" 2>$null
    Remove-Variable -Name "handle" 2>$null
})

$syncHash.Gui.btn_rStart.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$cm = $syncHash.Gui.tb_aName.text
    [int]$sid = 0

    if([string]::IsNullOrEmpty($cn) -or [string]::IsNullOrEmpty($cm)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target or filename/path is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($syncHash.Gui.tb_aSession.text)){
        $sid = 1
    } else {
        $sid = [int]$syncHash.Gui.tb_aSession.text
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0130]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    Start-Process -FilePath cmd.exe -Verb Runas -ArgumentList "/k PsExec.exe /accepteula /nobanner \\$cn -s -i $sid -d $cm & exit"
})

Function Get-DecodedVBE {
    <#
    .EXAMPLE
    Get-DecodedVBE -EncodedData "#@~^C2oAAA==v,sr^+,1ls+=~Hbo.lDkGUxW4k \(/@#@&v~.DkkGxl~ZRX@#@&vPzEO4KD)~PU&3@#@&v,ZGs:==^#~@"
    
    .EXAMPLE
    Get-Content "c:\encodedfile.vbe" | Get-DecodedVBE
    #>
    
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string]
        $EncodedData
    )
    
    try {
        # remove start and stop pattern
        $VbeData = $EncodedData -match '#@~\^......==(.+)......==\^#~@'
        if ($VbeData -eq $true) {
            $VbeData = $Matches[1]
            Write-Verbose "[Get-DecodedVBE] Found VBE trailing characters"    
        }
    
        # replace special characters
        $VbeData = $VbeData.Replace('@&',"`n").Replace('@#',"`r").Replace('@*','>').replace('@!','<').replace('@$','@')
    
        # initialize dict with static hex values as a list of three characters each, e.g. 65: ['w', 'E', 'B']
        $VbeDecList = @{
            "9" = 0x57,0x6E,0x7B
            "10" = 0x4A,0x4C,0x41
            "11" = 0x0B,0x0B,0x0B
            "12" = 0x0C,0x0C,0x0C
            "13" = 0x4A,0x4C,0x41
            "14" = 0x0E,0x0E,0x0E
            "15" = 0x0F,0x0F,0x0F
            "16" = 0x10,0x10,0x10
            "17" = 0x11,0x11,0x11
            "18" = 0x12,0x12,0x12
            "19" = 0x13,0x13,0x13
            "20" = 0x14,0x14,0x14
            "21" = 0x15,0x15,0x15
            "22" = 0x16,0x16,0x16
            "23" = 0x17,0x17,0x17
            "24" = 0x18,0x18,0x18
            "25" = 0x19,0x19,0x19
            "26" = 0x1A,0x1A,0x1A
            "27" = 0x1B,0x1B,0x1B
            "28" = 0x1C,0x1C,0x1C
            "29" = 0x1D,0x1D,0x1D
            "30" = 0x1E,0x1E,0x1E
            "31" = 0x1F,0x1F,0x1F
            "32" = 0x2E,0x2D,0x32
            "33" = 0x47,0x75,0x30
            "34" = 0x7A,0x52,0x21
            "35" = 0x56,0x60,0x29
            "36" = 0x42,0x71,0x5B
            "37" = 0x6A,0x5E,0x38
            "38" = 0x2F,0x49,0x33
            "39" = 0x26,0x5C,0x3D
            "40" = 0x49,0x62,0x58
            "41" = 0x41,0x7D,0x3A
            "42" = 0x34,0x29,0x35
            "43" = 0x32,0x36,0x65
            "44" = 0x5B,0x20,0x39
            "45" = 0x76,0x7C,0x5C
            "46" = 0x72,0x7A,0x56
            "47" = 0x43,0x7F,0x73
            "48" = 0x38,0x6B,0x66
            "49" = 0x39,0x63,0x4E
            "50" = 0x70,0x33,0x45
            "51" = 0x45,0x2B,0x6B
            "52" = 0x68,0x68,0x62
            "53" = 0x71,0x51,0x59
            "54" = 0x4F,0x66,0x78
            "55" = 0x09,0x76,0x5E
            "56" = 0x62,0x31,0x7D
            "57" = 0x44,0x64,0x4A
            "58" = 0x23,0x54,0x6D
            "59" = 0x75,0x43,0x71
            "60" = 0x4A,0x4C,0x41
            "61" = 0x7E,0x3A,0x60
            "62" = 0x4A,0x4C,0x41
            "63" = 0x5E,0x7E,0x53
            "64" = 0x40,0x4C,0x40
            "65" = 0x77,0x45,0x42
            "66" = 0x4A,0x2C,0x27
            "67" = 0x61,0x2A,0x48
            "68" = 0x5D,0x74,0x72
            "69" = 0x22,0x27,0x75
            "70" = 0x4B,0x37,0x31
            "71" = 0x6F,0x44,0x37
            "72" = 0x4E,0x79,0x4D
            "73" = 0x3B,0x59,0x52
            "74" = 0x4C,0x2F,0x22
            "75" = 0x50,0x6F,0x54
            "76" = 0x67,0x26,0x6A
            "77" = 0x2A,0x72,0x47
            "78" = 0x7D,0x6A,0x64
            "79" = 0x74,0x39,0x2D
            "80" = 0x54,0x7B,0x20
            "81" = 0x2B,0x3F,0x7F
            "82" = 0x2D,0x38,0x2E
            "83" = 0x2C,0x77,0x4C
            "84" = 0x30,0x67,0x5D
            "85" = 0x6E,0x53,0x7E
            "86" = 0x6B,0x47,0x6C
            "87" = 0x66,0x34,0x6F
            "88" = 0x35,0x78,0x79
            "89" = 0x25,0x5D,0x74
            "90" = 0x21,0x30,0x43
            "91" = 0x64,0x23,0x26
            "92" = 0x4D,0x5A,0x76
            "93" = 0x52,0x5B,0x25
            "94" = 0x63,0x6C,0x24
            "95" = 0x3F,0x48,0x2B
            "96" = 0x7B,0x55,0x28
            "97" = 0x78,0x70,0x23
            "98" = 0x29,0x69,0x41
            "99" = 0x28,0x2E,0x34
            "100" = 0x73,0x4C,0x09
            "101" = 0x59,0x21,0x2A
            "102" = 0x33,0x24,0x44
            "103" = 0x7F,0x4E,0x3F
            "104" = 0x6D,0x50,0x77
            "105" = 0x55,0x09,0x3B
            "106" = 0x53,0x56,0x55
            "107" = 0x7C,0x73,0x69
            "108" = 0x3A,0x35,0x61
            "109" = 0x5F,0x61,0x63
            "110" = 0x65,0x4B,0x50
            "111" = 0x46,0x58,0x67
            "112" = 0x58,0x3B,0x51
            "113" = 0x31,0x57,0x49
            "114" = 0x69,0x22,0x4F
            "115" = 0x6C,0x6D,0x46
            "116" = 0x5A,0x4D,0x68
            "117" = 0x48,0x25,0x7C
            "118" = 0x27,0x28,0x36
            "119" = 0x5C,0x46,0x70
            "120" = 0x3D,0x4A,0x6E
            "121" = 0x24,0x32,0x7A
            "122" = 0x79,0x41,0x2F
            "123" = 0x37,0x3D,0x5F
            "124" = 0x60,0x5F,0x4B
            "125" = 0x51,0x4F,0x5A
            "126" = 0x20,0x42,0x2C
            "127" = 0x36,0x65,0x57
            }
    
        # initialize dict with static int values as a static key to choose the character of the list above, therefore the values are from 0 to 2
        $VbePosList = @{
            "0" = 0
            "1" = 1
            "2" = 2
            "3" = 0
            "4" = 1
            "5" = 2
            "6" = 1
            "7" = 2
            "8" = 2
            "9" = 1
            "10" = 2
            "11" = 1
            "12" = 0
            "13" = 2
            "14" = 1
            "15" = 2
            "16" = 0
            "17" = 2
            "18" = 1
            "19" = 2
            "20" = 0
            "21" = 0
            "22" = 1
            "23" = 2
            "24" = 2
            "25" = 1
            "26" = 0
            "27" = 2
            "28" = 1
            "29" = 2
            "30" = 2
            "31" = 1
            "32" = 0
            "33" = 0
            "34" = 2
            "35" = 1
            "36" = 2
            "37" = 1
            "38" = 2
            "39" = 0
            "40" = 2
            "41" = 0
            "42" = 0
            "43" = 1
            "44" = 2
            "45" = 0
            "46" = 2
            "47" = 1
            "48" = 0
            "49" = 2
            "50" = 1
            "51" = 2
            "52" = 0
            "53" = 0
            "54" = 1
            "55" = 2
            "56" = 2
            "57" = 0
            "58" = 0
            "59" = 1
            "60" = 2
            "61" = 0
            "62" = 2
            "63" = 1
        }
    
        $CharIndex = -1
        foreach ($character in $VbeData.ToCharArray()) {
                # get hex value of character
            $Byte = [byte]$character
    
            # increase $index to change modulo result each run
            if ($Byte -lt 128) {
                $CharIndex += 1
            }
            # check if printable character and do the decoding
            if (($Byte -eq 9 -or $Byte -gt 31 -and $Byte -lt 128) -and ($Byte -ne 60 -and $Byte -ne 62 -and $Byte -ne 64)) {
                    $CombinationNumber = $($VbePosList["$($CharIndex % 64)"])
                    [char]$character = $($VbeDecList["$Byte"])[$CombinationNumber]
            }
            $DecodedVBE += $character -join ''
        }
        return $DecodedVBE     
    }
    catch {
        return "Invalid VBE"
    }
}

$syncHash.Gui.btn_vbe.Add_click({
    [string]$fileVBE = ""
    [string]$fileVBS = ""

    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $filename = New-Object System.Windows.Forms.OpenFileDialog
    $filename.initialDirectory = $PSScriptRoot
    $filename.Filter = "Text files(*.vbe)|*.vbe"

    if($filename.ShowDialog() -eq "OK") {
        $fileVBE = $filename.FileName
    } else {
        Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "No file selected." -NewLine $true
        return
    }
    $fileVBS = $fileVBE.substring(0,$fileVBE.length-1) + 's'

    $output = Get-Content $fileVBE | Get-DecodedVBE
    if($output -match "Invalid VBE"){
        Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text $output -NewLine $true
        return
    } else {
        $output | Out-File $fileVBS
        Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text "$fileVBS has been created." -NewLine $true
    }
})

$syncHash.Gui.btn_pSet.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [pscredential]$cred = $syncHash.PSRemote_credential

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($syncHash.Gui.tb_DC.text) -or [string]::IsNullOrEmpty($syncHash.Gui.tb_AC.text)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Wrong timeout value." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0131]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    [int]$DC = [int]$syncHash.Gui.tb_DC.text
    [int]$AC = [int]$syncHash.Gui.tb_AC.text

    if($cred){
        [String]$R = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock { 
            [String]$result = ""
            powercfg /SETDCVALUEINDEX SCHEME_CURRENT 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 $Using:DC
            powercfg /SETACVALUEINDEX SCHEME_CURRENT 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 $Using:AC
            $result = powercfg /Q SCHEME_CURRENT 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 | Out-String

            return $result
        }
    } else {
        [String]$R = Invoke-Command -ComputerName $cn -ScriptBlock { 
            [String]$result = ""
            powercfg /SETDCVALUEINDEX SCHEME_CURRENT 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 $Using:DC
            powercfg /SETACVALUEINDEX SCHEME_CURRENT 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 $Using:AC
            $result = powercfg /Q SCHEME_CURRENT 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 | Out-String

            return $result
        }
    }
    if($R){
        $R = $R -replace "`n",""
        Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text $R -NewLine $true
    } else {
        Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "Something wrong." -NewLine $true
    }
    Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text "Done" -NewLine $true
})

$syncHash.Gui.btn_store.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [pscredential]$cred = $syncHash.PSRemote_credential

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0132]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if($cred){
        [String]$R = Invoke-Command -ComputerName $cn -Credential $cred -ScriptBlock {
            [String]$e = ""
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'DisableStoreApps' -Value 0
            $e = $error[0]
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'RemoveWindowsStore' -Value 0
            $e = $e + $error[0]

            return $e
        }
    } else {
        [String]$R = Invoke-Command -ComputerName $cn -ScriptBlock {
            [String]$e = ""
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'DisableStoreApps' -Value 0
            $e = $error[0]
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'RemoveWindowsStore' -Value 0
            $e = $e + $error[0]

            return $e
        }
    }
    if($R){
        $R = $R -replace "`n",""
        Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text $R -NewLine $true
    } else {
        Show-Result -Font "Courier New" -Size "18" -Color "Lime" -Text "Command sent to the remote computer $cn." -NewLine $true
    }
    Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text "Done" -NewLine $true
})

$syncHash.Gui.btn_events.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [pscredential]$cred = $syncHash.PSRemote_credential

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0133]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    [string]$bat   = "QGVjaG8gb2ZmDQpGT1IgL0YgInRva2Vucz0xLDIqIiAlJVYgSU4gKCdiY2RlZGl0JykgRE8gU0VUIGFkbWluVGVzdD0lJVYNCklGICglYWRtaW5UZXN0JSk9PShBY2Nlc3MpIGdvdG8gbm9BZG1pbg0KZm9yIC9GICJ0b2tlbnM9KiIgJSVHIGluICgnd2V2dHV0aWwuZXhlIGVsJykgRE8gKGNhbGwgOmRvX2NsZWFyICIlJUciKQ0KZWNoby4NCmVjaG8gQWxsIEV2ZW50IExvZ3MgaGF2ZSBiZWVuIGNsZWFyZWQhDQpnb3RvIHRoZUVuZCAgICANCjpkb19jbGVhcg0KZWNobyBjbGVhcmluZyAlMQ0Kd2V2dHV0aWwuZXhlIGNsICUxDQpnb3RvIDplb2YgICAgDQo6bm9BZG1pbg0KZWNobyBDdXJyZW50IHVzZXIgcGVybWlzc2lvbnMgdG8gZXhlY3V0ZSB0aGlzIC5CQVQgZmlsZSBhcmUgaW5hZGVxdWF0ZS4NCmVjaG8gVGhpcyAuQkFUIGZpbGUgbXVzdCBiZSBydW4gd2l0aCBhZG1pbmlzdHJhdGl2ZSBwcml2aWxlZ2VzLg0KZWNobyBFeGl0IG5vdywgcmlnaHQgY2xpY2sgb24gdGhpcyAuQkFUIGZpbGUsIGFuZCBzZWxlY3QgIlJ1biBhcyBhZG1pbmlzdHJhdG9yIi4gIA0KcGF1c2UgPm51bCAgICANCjp0aGVFbmQNCmRlbCBjOlxXaW5kb3dzXFRlbXBcZWMuYmF0DQpFeGl0"
    [String]$cmb   = "Y21kLmV4ZSAvQyBjOlx3aW5kb3dzXHRlbXBcZWMuYmF0"
    [String]$cm    = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cmb))
    [string]$batch = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($bat))

    try{
        if($cred){
            $Session = New-PSSession -ComputerName $cn -Credential $cred
        } else {
            $Session = New-PSSession -ComputerName $cn
        }
    } catch {
        $e = "[Error 0134]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]            
        $msg = "Error: Cannot establish remote session with $cn, workflow terminated."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$error[0],$true
        return
    }

    try{
        Set-Content \\$cn\C$\Windows\temp\ec.bat $batch
    } catch {
        $e = "[Error 0135]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        $msg = "Error: Failed to copy ec.bat to $cn, workflow terminated."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$error[0],$true
        Remove-PSSession $Session
    }

    Remove-PSSession $Session
        
    Start-Process -FilePath cmd.exe -Verb Runas -ArgumentList "/k PsExec.exe /accepteula /nobanner \\$cn -s -d $cm & exit"

    Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text "Done" -NewLine $true
})

$syncHash.Install_DCPP = {
    [string]$logpath = "C:\temp\DCPP\DCPP-log.txt"

    New-Item -Path "c:\temp" -Name "DCPP" -ItemType "directory"

    Write-Output "=============== Task Sequence DCPP Begin =======================" | Out-File  $logpath -Append
    $dt = (get-date).tostring()
    Write-Output "{$dt} DCPP installing ..." | Out-File  $logpath -Append
    try{
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 # TLS 1.2 security protocal needed to authenticate with Microsoft server
        Install-PackageProvider -Name NuGet -Scope AllUsers -Force -Confirm:$false # -ErrorAction SilentlyContinue 
    } catch {
        $error[0] | Out-File  $logpath -Append
    }
    try{
        Install-Module -Name DellBIOSProvider -Scope AllUsers -Force -Confirm:$false #-ErrorAction SilentlyContinue 
    } catch {
        $error[0] | Out-File  $logpath -Append
    }
    $dt = (get-date).tostring()
    Write-Output "{$dt} Done." | Out-File  $logpath -Append
    Write-Output "=============== Task Sequence DCPP End =======================" | Out-File  $logpath -Append
}

$syncHash.InstallDCPP_scriptblock = {
    param(
        [string]$cn,
        [pscredential]$cred
    )

    try{
        if($cred){
            Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $syncHash.Install_DCPP -AsSystem
        } else {
            Invoke-CommandAs -ComputerName $cn -scriptblock $syncHash.Install_DCPP -AsSystem
        }
    }catch {
        $e = "[Error 0136]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        $msg = "Error: Failed to install DCPP module on $cn, workflow terminated."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$error[0],$true

        return
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","=====",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","DCPP module has been installed on $cn successfully.",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","=====",$true
    $syncHash.Control.InstallDCPP_scriptblock_Completed = $true
}

$syncHash.Gui.btn_InstallDCPP.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0137]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_InstallDCPP.IsEnabled  = $false
    $syncHash.Gui.cb_DellSMBIOS.IsEnabled    = $false
    $syncHash.Gui.btn_ListCatagory.IsEnabled = $false
    $syncHash.Gui.btn_Get.IsEnabled          = $false
    $syncHash.Gui.btn_Set.IsEnabled          = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.InstallDCPP_scriptblock).AddArgument($cn).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.DellSMBIOS_Get_Item = {
    param(
        [string]$item
    )

    Import-Module DellBIOSProvider

    $iList = Get-ChildItem "DellSMBIOS:$item" 2>&1 3>&1 4>&1 5>&1

    $iList
}

$syncHash.DellSMBIOS_Get_BootSequence = {
    Import-Module DellBIOSProvider

    $iList = Get-ChildItem "DellSMBIOS:BootSequence" | Select-Object -expand CurrentValue

    $iList
}

$syncHash.DellSMBIOS_Get_Item_scriptblock = {
    param(
        [string]$cn,
        [string]$item,
        [pscredential]$cred
    )

    try{
        if($cred){
            $iList = Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $syncHash.DellSMBIOS_Get_Item -ArgumentList $item -AsSystem
        } else {
            $iList = Invoke-CommandAs -ComputerName $cn -scriptblock $syncHash.DellSMBIOS_Get_Item -ArgumentList $item -AsSystem
        }
    }catch {
        $e = "[Error 0138]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        $msg = "Error: Failed to retrieve information on $cn, workflow terminated."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$error[0],$true

        $syncHash.Control.DellSMBIOS_Get_Item_scriptblock_Completed = $true

        return
    }

    if($iList.gettype().Name -match "PSCustomObject"){ # Catagory has no attribute
        $iList = $iList.trim()
        $msg = $msg -replace "`n",""
        $msg = $msg.trim()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$iList,$true

        $syncHash.Control.DellSMBIOS_Get_Item_scriptblock_Completed = $true

        return
    }

    $syncHash.AttributeList.clear()
    $iList | ForEach-Object {
        $t = $_ | Select-Object Attribute
        $syncHash.AttributeList.add($t.Attribute)
    }

    $msg = $iList | Select-Object Attribute,ShortDescription,CurrentValue,PossibleValues | Out-String -Width 1000
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","          ",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","===== $item =====",$true
    $msg = $msg.trim()
    $msg = $msg -replace "`n",""
    $msg = $msg.trim()
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$msg,$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","          ",$true

    if($item -eq "BootSequence"){
        if($cred){
            $iList = Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $syncHash.DellSMBIOS_Get_BootSequence -AsSystem
        } else {
            $iList = Invoke-CommandAs -ComputerName $cn -scriptblock $syncHash.DellSMBIOS_Get_BootSequence -AsSystem
        }
        $msg = $iList | Select-Object DeviceName,DeviceNumber,ShortForm,IsActive | Out-String -Width 1000
        $msg = $msg.trim()
        $msg = $msg -replace "`n",""
        $msg = $msg.trim()
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","          ",$true
    }
    $syncHash.Control.DellSMBIOS_Get_Item_scriptblock_Completed = $true
}

$syncHash.Gui.btn_Get.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$si = $syncHash.Gui.cb_DellSMBIOS.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($si)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Catagory is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0139]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_InstallDCPP.IsEnabled  = $False
    $syncHash.Gui.cb_DellSMBIOS.IsEnabled    = $False
    $syncHash.Gui.btn_ListCatagory.IsEnabled = $False
    $syncHash.Gui.btn_Get.IsEnabled          = $False
    $syncHash.Gui.btn_Set.IsEnabled          = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.DellSMBIOS_Get_Item_scriptblock).AddArgument($cn).AddArgument($syncHash.Gui.cb_DellSMBIOS.SelectedItem.tostring()).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.DellSMBIOS_Get_List = {

    Import-Module DellBIOSProvider

    $oList = Get-ChildItem DellSMBIOS: | Select-Object Category,Description
    $oList
}

$syncHash.DellSMBIOS_Get_List_scriptblock = {
    param(
        [string]$cn,
        [pscredential]$cred
    )

    try{
        if($cred){
            $oList = Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $syncHash.DellSMBIOS_Get_List -AsSystem
        } else {
            $oList = Invoke-CommandAs -ComputerName $cn -scriptblock $syncHash.DellSMBIOS_Get_List -AsSystem
        }
    }catch {
        $e = "[Error 0140]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        $msg = "Error: Failed to retrieve information on $cn, workflow terminated."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$error[0],$true

        $syncHash.Control.DellSMBIOS_Get_Item_scriptblock_Completed = $true
        $syncHash.Control.DellSMBIOS_Catagory_List_Ready = $true

        return
    }

    $msg = $oList | Select-Object Category,Description | out-string -Width 1000
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","          ",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","===== Supported Catagory List =====",$true
    $msg = $msg.trim()
    $msg = $msg -replace "`n",""
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$msg,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","=========================================================================================================",$true

    $syncHash.CatagoryList.clear()
    $syncHash.AttributeList.clear()

    $cList = $oList | Select-Object Category
    $cList | ForEach-Object{
        $msg = $_.Category | Out-String
        $msg = $msg.trim()
        $syncHash.CatagoryList.add($msg)
    }

    $DellSMBIOS_Get_Password_Status = {
        param(
            [string]$Attribute
        )
    
        Import-Module DellBIOSProvider
    
        $att = Get-ChildItem "DellSMBIOS:Security\\$Attribute" 2>&1 3>&1 4>&1 5>&1
    
        $att
    }

    try{
        if($cred){
            $adm = Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $DellSMBIOS_Get_Password_Status -ArgumentList "IsAdminPasswordSet" -AsSystem
        } else {
            $adm = Invoke-CommandAs -ComputerName $cn -scriptblock $DellSMBIOS_Get_Password_Status -ArgumentList "IsAdminPasswordSet" -AsSystem
        }
    } catch {
        $e = "[Error 0149]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        $msg = "Error: Failed to retrieve information on $cn, workflow terminated."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$error[0],$true

        $syncHash.Control.DellSMBIOS_Get_Item_scriptblock_Completed = $true
        $syncHash.Control.DellSMBIOS_Catagory_List_Ready = $true

        return
    }

    try{
        if($cred){
            $sys = Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $DellSMBIOS_Get_Password_Status -ArgumentList "IsSystemPasswordSet" -AsSystem
        } else {
            $sys = Invoke-CommandAs -ComputerName $cn -scriptblock $DellSMBIOS_Get_Password_Status -ArgumentList "IsSystemPasswordSet" -AsSystem
        }
    } catch {
        $e = "[Error 0150]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        $msg = "Error: Failed to retrieve information on $cn, workflow terminated."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$error[0],$true

        $syncHash.Control.DellSMBIOS_Get_Item_scriptblock_Completed = $true
        $syncHash.Control.DellSMBIOS_Catagory_List_Ready = $true

        return
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","===== Password Status =====",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan"," Admin : ",$false
    if($adm.CurrentValue -eq "True") {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","set",$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","No",$true
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan"," System: ",$false
    if($sys.CurrentValue -eq "True") {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red","set",$true
    } else {
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","No",$true
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","===========================",$true

    $syncHash.Control.DellSMBIOS_Get_Item_scriptblock_Completed = $true
    $syncHash.Control.DellSMBIOS_Catagory_List_Ready = $true
}

$syncHash.Gui.btn_ListCatagory.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0141]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_InstallDCPP.IsEnabled  = $False
    $syncHash.Gui.cb_DellSMBIOS.IsEnabled    = $False
    $syncHash.Gui.btn_ListCatagory.IsEnabled = $False
    $syncHash.Gui.btn_Get.IsEnabled          = $False
    $syncHash.Gui.btn_Set.IsEnabled          = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.DellSMBIOS_Get_List_scriptblock).AddArgument($cn).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.Gui.cb_DellSMBIOS.add_SelectionChanged({
    $syncHash.Gui.cb_Attributes.items.clear()
    $syncHash.Gui.tb_Attributes.text = ""
})

$syncHash.Gui.cb_Attributes.add_SelectionChanged({
    $syncHash.Gui.tb_Attributes.text = ""
})

$syncHash.DellSMBIOS_Set_Attribute = {
    param(
        [string]$ca, # Catagory
        [string]$at, # Attribute
        [string]$va, # Value
        [string]$ap, # Admin Password
        [String]$sp  # System Password
    )

    Import-Module DellBIOSProvider

    $att_path = "DellSmbios:\\$ca\\$at"
    if($att_path -match "AdminPassword"){
        if([string]::IsNullOrEmpty($ap)){
            if([string]::IsNullOrEmpty($va)){
                $err = Set-Item $att_path -Value "" 2>&1 | Out-String
            }else{
                $err = Set-Item $att_path -Value $va 2>&1 | Out-String
            }
        }else{
            if([string]::IsNullOrEmpty($va)){
                $err = Set-Item $att_path -Value "" -Password $ap 2>&1 | Out-String
            }else{
                $err = Set-Item $att_path -Value $va -Password $ap 2>&1 | Out-String
            }
        }
    }elseif($att_path -match "SystemPassword") {
        if([string]::IsNullOrEmpty($sp)){
            if([string]::IsNullOrEmpty($va)){
                $err = Set-Item $att_path -Value "" 2>&1 | Out-String
            }else{
                $err = Set-Item $att_path -Value $va 2>&1 | Out-String
            }
        }else{
            if([string]::IsNullOrEmpty($va)){
                $err = Set-Item $att_path -Value "" -Password $sp 2>&1 | Out-String
            }else{
                $err = Set-Item $att_path -Value $va -Password $sp 2>&1 | Out-String
            }
        }
    }else{
        if([string]::IsNullOrEmpty($ap)){
            $err = Set-Item $att_path -Value $va 2>&1 | Out-String
        }else {
            $err = Set-Item $att_path -Value $va -Password $ap 2>&1 | Out-String
        }
    }

    $err = $err -replace "`n",""
    $err = $err.trim()
    $err
}

$syncHash.DellSMBIOS_Set_Item_scriptblock = {
    param(
        [string]$cn, # Computer name
        [string]$ca, # Catagory
        [string]$at, # Attribute
        [string]$va, # Value
        [string]$ap, # Admin Password
        [String]$sp, # System Password
        [pscredential]$cred
    )

    try{
        if($cred) {
            $err = Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $syncHash.DellSMBIOS_Set_Attribute -ArgumentList $ca,$at,$va,$ap,$sp -AsSystem
        } else {
            $err = Invoke-CommandAs -ComputerName $cn -scriptblock $syncHash.DellSMBIOS_Set_Attribute -ArgumentList $ca,$at,$va,$ap,$sp -AsSystem
        }
    }catch {
        $e = "[Error 0142]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        $msg = "Error: Failed to retrieve information on $cn, workflow terminated."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$error[0],$true

        $syncHash.Control.DellSMBIOS_Set_Item_scriptblock_Completed = $true

        return
    }
    if($err){
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$err,$true
    }else{
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Attribute value set.",$true
    }
    $syncHash.Control.DellSMBIOS_Set_Item_scriptblock_Completed = $true
}

$syncHash.Gui.btn_Set.Add_click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$ca = $syncHash.Gui.cb_DellSMBIOS.text
    [string]$at = $syncHash.Gui.cb_Attributes.text
    [string]$va = $syncHash.Gui.tb_Attributes.text
    [string]$ap = $syncHash.Gui.pb_DellBiosAdminPsw.text
    [String]$sp = $syncHash.Gui.pb_DellBiosSysPsw.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($ca)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Catagory is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($at)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Attribute is blank." -NewLine $true
        return
    }

    if(([string]::IsNullOrEmpty($va)) -and (($at -ne "AdminPassword") -and ($at -ne "SystemPassword"))){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Value is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0143]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_InstallDCPP.IsEnabled  = $False
    $syncHash.Gui.cb_DellSMBIOS.IsEnabled    = $False
    $syncHash.Gui.btn_ListCatagory.IsEnabled = $False
    $syncHash.Gui.btn_Get.IsEnabled          = $False
    $syncHash.Gui.btn_Set.IsEnabled          = $False

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.DellSMBIOS_Set_Item_scriptblock).AddArgument($cn).AddArgument($ca).AddArgument($at).AddArgument($va).AddArgument($ap).AddArgument($sp).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GUI.btn_LoadPath.Add_Click({
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $filename = New-Object System.Windows.Forms.OpenFileDialog
    $filename.initialDirectory = "C:\Script_Collection"
    $filename.Filter = "Batch files(*.bat)|*.bat|Powershell files(*.ps1)|*.ps1|All files (*.*)|*.*"

    if($filename.ShowDialog() -eq "OK") {
        $syncHash.Gui.tb_Script_Path.text = $filename.FileName
    } else {
        return
    }
})

$syncHash.GUI.btn_Push2Run.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$pa = $syncHash.Gui.tb_Script_Path.text
    $file = Split-Path $pa -leaf
    [pscredential]$cred = $syncHash.PSRemote_credential

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($pa)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Script path is blank." -NewLine $true
        return
    }

    if(!(Test-Path $pa -PathType Leaf)){
        Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text " $Global:emoji_hand File specified doesn't exist." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0144]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    try{
        if($cred) {
            $Session = New-PSSession -ComputerName $cn -Credential $cred
        } else {
            $Session = New-PSSession -ComputerName $cn
        }
    } catch {
        $e = "[Error 0145]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        $msg = "Error: Cannot establish remote session with $cn, workflow terminated."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$error[0],$true
        return
    }

    try{
        Copy-Item -Path $pa -Destination "C:\Windows\temp" -ToSession $session -Force -ErrorAction Ignore -WarningAction Ignore -InformationAction Ignore | Out-Null
    } catch {
        $e = "[Error 0146]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        $msg = "Error: Failed to copy file to $cn, workflow terminated."
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$msg,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Red",$error[0],$true
        Remove-PSSession $Session
        return
    }

    Remove-PSSession $Session
    $PSBlock = {
        param(
            [string]$file
        )
        Start-Process -Filepath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argumentlist "-NonInteractive -WindowStyle Hidden -NoLogo -NoProfile -NoExit -ExecutionPolicy bypass -file C:\Windows\temp\$file" -NoNewWindow
    }

    $BATBlock = {
        param(
            [string]$file
        )
        Start-Process -Filepath "cmd.exe" -Argumentlist "/c C:\Windows\temp\$file" -NoNewWindow
    }
    
    if($file -match ".bat"){
        if($cred) {
            Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $BATBlock -ArgumentList $file -AsSystem
        } else {
            Invoke-CommandAs -ComputerName $cn -scriptblock $BATBlock -ArgumentList $file -AsSystem
        }
    }elseif($file -match ".ps1"){
        if($cred) {
            $result = Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $PSBlock  -ArgumentList $file -AsSystem
        } else {
            $result = Invoke-CommandAs -ComputerName $cn -scriptblock $PSBlock  -ArgumentList $file -AsSystem
        }
        Show-Result -Font "Courier New" -Size "18" -Color "Cyan" -Text $result -NewLine $true
    }
})

$syncHash.CheckCurrentRC_scriptblock = {
    param(
        [string]$cn,
        [pscredential]$cred
    )

    $worker = {
        $CrashBehaviour = Get-WmiObject Win32_OSRecoveryConfiguration -EnableAllPrivileges
        $result = $CrashBehaviour | Format-List * | out-string
        $result = $result -replace "`n",""
        $result = $result.Trim()

        $result
    }

    if($cred){
        $info = Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $worker -AsSystem
    } else {
        $info = Invoke-CommandAs -ComputerName $cn -scriptblock $worker -AsSystem
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","===== Current Recovery Configuration =====",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$info,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","==========================================",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","                                          ",$true

    $syncHash.Control.System_Recovery_Configuration_Completed   = $true
}

$syncHash.GUI.btn_GetConfig.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0147]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_Analyze.IsEnabled     = $false
    $syncHash.Gui.cb_AutoReboot.IsEnabled   = $false
    $syncHash.Gui.cb_SysLog.IsEnabled       = $false
    $syncHash.Gui.cb_Overwrite.IsEnabled    = $false
    $syncHash.Gui.btn_GetConfig.IsEnabled   = $false
    $syncHash.Gui.cb_RecoveryConf.IsEnabled = $false
    $syncHash.Gui.btn_ApplyChange.IsEnabled = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.CheckCurrentRC_scriptblock).AddArgument($cn).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.UpdateRC_scriptblock = {
    Param (
        [string]$cn,       # Computer name
        [int]$rc,          # Recovery configuration
        [bool]$AutoReboot, # Auto Reboot
        [bool]$SysLog,     # Write to system log
        [bool]$OverWrite,  # Overwrite existing debug files
        [pscredential]$cred
    )

    $worker = {
        Param (
            [int]$rc,          # Recovery configuration
            [bool]$AutoReboot, # Auto Reboot
            [bool]$SysLog,     # Write to system log
            [bool]$OverWrite   # Overwrite existing debug files
        )

        $CrashBehaviour = Get-WmiObject Win32_OSRecoveryConfiguration -EnableAllPrivileges
        $CrashBehaviour.AutoReboot                 = $AutoReboot
        $CrashBehaviour.DebugInfoType              = $rc
        $CrashBehaviour.WriteToSystemLog           = $SysLog
        $CrashBehaviour.OverwriteExistingDebugFile = $OverWrite
        $CrashBehaviour | Set-WmiInstance

        $CrashBehaviour = Get-WmiObject Win32_OSRecoveryConfiguration -EnableAllPrivileges
        $result = $CrashBehaviour | Format-List * | out-string
        $result = $result -replace "`n",""
        $result = $result.Trim()

        $result
    }

    if($cred){
        $info = Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $worker -ArgumentList $rc,$AutoReboot,$SysLog -AsSystem
    } else {
        $info = Invoke-CommandAs -ComputerName $cn -scriptblock $worker -ArgumentList $rc,$AutoReboot,$SysLog -AsSystem
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","===== Current Recovery Configuration =====",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$info,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","==========================================",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","                                          ",$true

    $syncHash.Control.System_Recovery_Configuration_Completed   = $true
}

$syncHash.GUI.btn_ApplyChange.Add_Click({
    [string]$cn       = $syncHash.Gui.cb_Target.text
    [string]$rct      = $syncHash.Gui.cb_RecoveryConf.text
    [bool]$AutoReboot = $syncHash.Gui.cb_AutoReboot.IsChecked
    [bool]$SysLog     = $syncHash.Gui.cb_SysLog.IsChecked
    [bool]$OverWrite  = $syncHash.Gui.cb_Overwrite.IsChecked
    [int]$rc = 0

    if([string]::IsNullOrEmpty($rct)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Please select your recovery configuration." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0148]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    switch ($rct)
    {
        {$rct -match "None"}                   {$rc = 0}
        {$rct -match "Complete memory dump"}   {$rc = 1}
        {$rct -match "Kernel memory dump"}     {$rc = 2}
        {$rct -match "Small memory dump"}      {$rc = 3}
        {$rct -match "Automatic Memory Dump"}  {$rc = 4}
    }

    # Disable wedgets
    $syncHash.Gui.btn_Analyze.IsEnabled     = $false
    $syncHash.Gui.cb_AutoReboot.IsEnabled   = $false
    $syncHash.Gui.cb_SysLog.IsEnabled       = $false
    $syncHash.Gui.cb_Overwrite.IsEnabled    = $false
    $syncHash.Gui.btn_GetConfig.IsEnabled   = $false
    $syncHash.Gui.cb_RecoveryConf.IsEnabled = $false
    $syncHash.Gui.btn_ApplyChange.IsEnabled = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.UpdateRC_scriptblock).AddArgument($cn).AddArgument($rc).AddArgument($AutoReboot).AddArgument($SysLog).AddArgument($OverWrite).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

########### HP bios remote management
$syncHash.HPCMSL_scriptblock = {
    Param (
        [string]$cn,
        [pscredential]$cred
    )

    $worker = {
        try{
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 # TLS 1.2 security protocal needed to authenticate with Microsoft server
            Install-PackageProvider -Name NuGet -Scope AllUsers -Force -Confirm:$false # -ErrorAction SilentlyContinue 
        } catch {
        }
        try{
            $v = Find-Module -Name PowershellGet -AllVersions
            Update-Module -Name PowerShellGet -RequiredVersion $v[0].Version -Force -Confirm:$false
            Install-Module -Name HPCMSL -Scope AllUsers -Force -Confirm:$false -AcceptLicense
        } catch {
        }
        try{
            Invoke-WebRequest -Uri https://hpia.hpcloud.hp.com/downloads/cmsl/hp-cmsl-1.6.3.exe -OutFile c:\windows\temp\hp-cmsl.exe
            c:\windows\temp\hp-cmsl.exe /VERYSILENT
            Remove-item -Path c:\windows\temp\hp-cmsl.exe -Force -Confirm:$false
        } catch {
        }
    }

    if($cred){
        Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $worker -AsSystem
    } else {
        Invoke-CommandAs -ComputerName $cn -scriptblock $worker -AsSystem
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","=====",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","HPCMSL module has been installed on $cn successfully.",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","=====",$true

    $syncHash.Control.HPCMSL_scriptblock_Completed   = $true
}

$syncHash.GUI.btn_HPCMSL.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0151]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_HPCMSL.IsEnabled        = $false
    $syncHash.Gui.tb_att.IsEnabled            = $false
    $syncHash.Gui.tb_val.IsEnabled            = $false
    $syncHash.Gui.btn_HpGet.IsEnabled         = $false
    $syncHash.Gui.btn_HpSet.IsEnabled         = $false
    $syncHash.Gui.pb_HpBiosAdminPsw.IsEnabled = $false
    $syncHash.Gui.pb_HpBiosSysPsw.IsEnabled   = $false
    $syncHash.Gui.btn_HpList.IsEnabled        = $false
    $syncHash.Gui.btn_HpClear.IsEnabled       = $false
    $syncHash.Gui.cb_HPBIOSVersions.IsEnabled = $false
    $syncHash.Gui.btn_HpBiosFlash.IsEnabled   = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.HPCMSL_scriptblock).AddArgument($cn).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.HpList_scriptblock = {
    Param (
        [string]$cn,
        [pscredential]$cred
    )

    $worker = {
        $SettingList = Get-WmiObject -Namespace root\HP\InstrumentedBIOS -Class HP_BIOSEnumeration  2>&1 3>&1 4>&1 5>&1

        $List = $SettingList | Select-Object Name,Value  | Sort-Object -Property name | Out-String -Width 1000

        $List = $List -replace "`n",""
        $List = $List.Trim()
        $List = $List + "`n"

        $pss = Get-HPBIOSSetupPasswordIsSet
        $List = $List + "Setup Password Present    : " + $pss + "`r"

        $pss = Get-HPBIOSPowerOnPasswordIsSet
        $List = $List + "Power On Password Present : " + $pss + "`n"

        $pss = Get-HPBIOSUUID
        $List = $List + "BIOS UUID     : " + $pss + "`r"
        $pss = Get-HPDeviceUUID
        $List = $List + "Device UUID   : " + $pss + "`r"
        $pss = Get-HPBIOSVersion
        $List = $List + "BIOS Version  : " + $pss + "`r"
        $pss = Get-HPDeviceAssetTag
        $List = $List + "Asset Tag     : " + $pss + "`r"
        $pss = Get-HPDeviceModel
        $List = $List + "Device Model  : " + $pss + "`r"
        $pss = Get-HPDevicePartNumber
        $List = $List + "Part Number   : " + $pss + "`r"
        $pss = Get-HPDeviceProductID
        $List = $List + "Product ID    : " + $pss + "`r"
        $pss = Get-HPDeviceSerialNumber
        $List = $List + "Serial Number : " + $pss + "`r"
        $pss = Get-HPBIOSAuthor
        $List = $List + "Manufacture   : " + $pss + "`r`n"
        $pss = Get-HPDeviceBootInformation | Out-String
        $pss = $pss -replace "`n",""
        $pss = $pss.Trim()
        $List = $List + "Boot info     :" + "`r"
        $List = $List + $pss
        
        $List
    }

    if($cred){
        $result = Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $worker -AsSystem
    } else {
        $result = Invoke-CommandAs -ComputerName $cn -scriptblock $worker -AsSystem
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","===================== All supported BIOS attributes list ======================",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Values include all possible values and the current values (with a leading star)",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","===============================================================================",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$result,$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","===============================================================================",$true
    
    $syncHash.Control.HPCMSL_scriptblock_Completed   = $true
}

$syncHash.GUI.btn_HpList.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0152]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_HPCMSL.IsEnabled        = $false
    $syncHash.Gui.tb_att.IsEnabled            = $false
    $syncHash.Gui.tb_val.IsEnabled            = $false
    $syncHash.Gui.btn_HpGet.IsEnabled         = $false
    $syncHash.Gui.btn_HpSet.IsEnabled         = $false
    $syncHash.Gui.pb_HpBiosAdminPsw.IsEnabled = $false
    $syncHash.Gui.pb_HpBiosSysPsw.IsEnabled   = $false
    $syncHash.Gui.btn_HpList.IsEnabled        = $false
    $syncHash.Gui.btn_HpClear.IsEnabled       = $false
    $syncHash.Gui.cb_HPBIOSVersions.IsEnabled = $false
    $syncHash.Gui.btn_HpBiosFlash.IsEnabled   = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.HpList_scriptblock).AddArgument($cn).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.HpGet_scriptblock = {
    Param (
        [string]$cn,
        [string]$att,
        [pscredential]$cred
    )

    $worker = {
        Param (
            [string]$at
        )

        $HPBiosSettings = Get-WmiObject -Namespace root\HP\InstrumentedBIOS -Class HP_BIOSSetting
        $result = ($HPBiosSettings | Where-Object Name -eq $at).Value

        $result
    }

    if($cred){
        $result = Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $worker -ArgumentList $att -AsSystem
    } else {
        $result = Invoke-CommandAs -ComputerName $cn -scriptblock $worker -ArgumentList $att -AsSystem
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","===========================================",$true
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","$att = ",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$result,$true

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","===========================================",$true
    
    $syncHash.Control.HPCMSL_scriptblock_Completed   = $true
}

$syncHash.GUI.btn_HpGet.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$at = $syncHash.Gui.tb_att.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($at)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Attribute is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0153]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_HPCMSL.IsEnabled        = $false
    $syncHash.Gui.tb_att.IsEnabled            = $false
    $syncHash.Gui.tb_val.IsEnabled            = $false
    $syncHash.Gui.btn_HpGet.IsEnabled         = $false
    $syncHash.Gui.btn_HpSet.IsEnabled         = $false
    $syncHash.Gui.pb_HpBiosAdminPsw.IsEnabled = $false
    $syncHash.Gui.pb_HpBiosSysPsw.IsEnabled   = $false
    $syncHash.Gui.btn_HpList.IsEnabled        = $false
    $syncHash.Gui.btn_HpClear.IsEnabled       = $false
    $syncHash.Gui.cb_HPBIOSVersions.IsEnabled = $false
    $syncHash.Gui.btn_HpBiosFlash.IsEnabled   = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.HpGet_scriptblock).AddArgument($cn).AddArgument($at).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.HpSet_scriptblock = {
    Param (
        [string]$cn,
        [string]$att,
        [string]$val,
        [string]$pas,
        [pscredential]$cred
    )

    $worker = {
        Param (
            [string]$at,
            [string]$va,
            [String]$pa
        )

        $Interface = Get-WmiObject -Namespace root\HP\InstrumentedBIOS -Class HP_BIOSSettingInterface
        if([string]::IsNullOrEmpty($pa)){
            $result = $Interface.SetBIOSSetting($at,$va)
        } else {
            $result = $Interface.SetBIOSSetting($at,$va,"<utf-16/>"+$pa)
        }
        
        $ret = $result.Return

        $ret
    }

    if($cred){
        $result = Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $worker -ArgumentList $att,$val,$pas -AsSystem
    } else {
        $result = Invoke-CommandAs -ComputerName $cn -scriptblock $worker -ArgumentList $att,$val,$pas -AsSystem
    }

    if($result -eq 0) {
        $color = "Cyan"
    } else {
        $color = "Red"
    }
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","Return = ",$false
    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18",$color,$result,$true

    $syncHash.Control.HPCMSL_scriptblock_Completed   = $true
}

$syncHash.GUI.btn_HpSet.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$at = $syncHash.Gui.tb_att.text
    [string]$va = $syncHash.Gui.tb_val.text
    [string]$pa = $syncHash.Gui.pb_HpBiosAdminPsw.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($at)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Attribute is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($va)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Value is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0154]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_HPCMSL.IsEnabled        = $false
    $syncHash.Gui.tb_att.IsEnabled            = $false
    $syncHash.Gui.tb_val.IsEnabled            = $false
    $syncHash.Gui.btn_HpGet.IsEnabled         = $false
    $syncHash.Gui.btn_HpSet.IsEnabled         = $false
    $syncHash.Gui.pb_HpBiosAdminPsw.IsEnabled = $false
    $syncHash.Gui.pb_HpBiosSysPsw.IsEnabled   = $false
    $syncHash.Gui.btn_HpList.IsEnabled        = $false
    $syncHash.Gui.btn_HpClear.IsEnabled       = $false
    $syncHash.Gui.cb_HPBIOSVersions.IsEnabled = $false
    $syncHash.Gui.btn_HpBiosFlash.IsEnabled   = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.HpSet_scriptblock).AddArgument($cn).AddArgument($at).AddArgument($va).AddArgument($pa).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.HpClear_scriptblock = {
    Param (
        [string]$cn,
        [string]$pa,
        [string]$ps,
        [pscredential]$cred
    )

    $worker = {
        Param (
            [string]$pa,
            [String]$ps
        )

        if(!([string]::IsNullOrEmpty($pa))){
            Clear-HPBIOSSetupPassword  -Password $pa
        }

        if(!([string]::IsNullOrEmpty($ps))){
            Clear-HPBIOSPowerOnPassword -Password $ps
        }
    }

    if($cred){
        Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $worker -ArgumentList $pa,$ps -AsSystem
    } else {
        Invoke-CommandAs -ComputerName $cn -scriptblock $worker -ArgumentList $pa,$ps -AsSystem
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","Command sent. Please check the result.",$true

    $syncHash.Control.HPCMSL_scriptblock_Completed = $true
}

$syncHash.GUI.btn_HpClear.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$pa = $syncHash.Gui.pb_HpBiosAdminPsw.text
    [string]$ps = $syncHash.Gui.pb_HpBiosSysPsw.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($pa) -and [string]::IsNullOrEmpty($ps)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Password is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0155]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_HPCMSL.IsEnabled        = $false
    $syncHash.Gui.tb_att.IsEnabled            = $false
    $syncHash.Gui.tb_val.IsEnabled            = $false
    $syncHash.Gui.btn_HpGet.IsEnabled         = $false
    $syncHash.Gui.btn_HpSet.IsEnabled         = $false
    $syncHash.Gui.pb_HpBiosAdminPsw.IsEnabled = $false
    $syncHash.Gui.pb_HpBiosSysPsw.IsEnabled   = $false
    $syncHash.Gui.btn_HpList.IsEnabled        = $false
    $syncHash.Gui.btn_HpClear.IsEnabled       = $false
    $syncHash.Gui.cb_HPBIOSVersions.IsEnabled = $false
    $syncHash.Gui.btn_HpBiosFlash.IsEnabled   = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.HpClear_scriptblock).AddArgument($cn).AddArgument($pa).AddArgument($ps).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.HpPwd_scriptblock = {
    Param (
        [string]$cn,
        [string]$pa,
        [string]$ps,
        [string]$op,
        [pscredential]$cred
    )

    $worker = {
        Param (
            [string]$pa,
            [String]$ps,
            [String]$op
        )

        if(!([string]::IsNullOrEmpty($pa))){
            if([string]::IsNullOrEmpty($op)){
                Set-HPBIOSSetupPassword -NewPassword $pa
            } else {
                Set-HPBIOSSetupPassword -NewPassword $pa -Password $op
            }
        }

        if([string]::IsNullOrEmpty($ps)){
            if([string]::IsNullOrEmpty($op)){
                Set-HPBIOSPowerOnPassword -NewPassword $ps
            } else {
                Set-HPBIOSPowerOnPassword -NewPassword $ps -Password $op
            }
        }
    }

    if($cred){
        Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $worker -ArgumentList $pa,$ps,$op -AsSystem
    } else {
        Invoke-CommandAs -ComputerName $cn -scriptblock $worker -ArgumentList $pa,$ps,$op -AsSystem
    }

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","Command sent.",$true

    $syncHash.Control.HPCMSL_scriptblock_Completed = $true
}

$syncHash.GUI.btn_HpPwd.Add_Click({
    [string]$cn = $syncHash.Gui.cb_Target.text
    [string]$pa = $syncHash.Gui.pb_HpBiosAdminPsw.text
    [string]$ps = $syncHash.Gui.pb_HpBiosSysPsw.text
    [string]$op = $syncHash.Gui.tb_val.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    if([string]::IsNullOrEmpty($pa) -and [string]::IsNullOrEmpty($ps)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Please provide new Setup/PowerOn password." -NewLine $true
        return
    }

    if(!([string]::IsNullOrEmpty($pa)) -and !([string]::IsNullOrEmpty($ps))){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand You can only set/change ONE password at a time." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0155]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_HPCMSL.IsEnabled        = $false
    $syncHash.Gui.tb_att.IsEnabled            = $false
    $syncHash.Gui.tb_val.IsEnabled            = $false
    $syncHash.Gui.btn_HpGet.IsEnabled         = $false
    $syncHash.Gui.btn_HpSet.IsEnabled         = $false
    $syncHash.Gui.pb_HpBiosAdminPsw.IsEnabled = $false
    $syncHash.Gui.pb_HpBiosSysPsw.IsEnabled   = $false
    $syncHash.Gui.btn_HpList.IsEnabled        = $false
    $syncHash.Gui.btn_HpClear.IsEnabled       = $false
    $syncHash.Gui.cb_HPBIOSVersions.IsEnabled = $false
    $syncHash.Gui.btn_HpBiosFlash.IsEnabled   = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.HpPwd_scriptblock).AddArgument($cn).AddArgument($pa).AddArgument($ps).AddArgument($op).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.HpBiosFlash_scriptblock = {
    param(
        [string]$cn,
        [string]$ve,
        [string]$pa,
        [bool]$flash,
        [pscredential]$cred
    )

    $getList = {
        $li = Get-HPBIOSUpdates
        $li
    }

    $flashBios = {
        param(
            [string]$ve,
            [string]$pa
        )

        if([string]::IsNullOrEmpty($pa)){
            Get-HPBIOSUpdates -Flash -Version $ve -BitLocker Suspend -Yes
        } else {
            Get-HPBIOSUpdates -Flash -Version $ve -Password $pa -BitLocker Suspend -Yes
        }

        Restart-Computer -Force
    }

    if(!$flash){
        if($cred){
            $LO = Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $getList -AsSystem
        } else {
            $LO = Invoke-CommandAs -ComputerName $cn -scriptblock $getList -AsSystem
        }

        $List = $LO | Select-Object Ver,Date,Bin  | Out-String
        $List = $List -replace "`n",""
        $List = $List.Trim()

        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","====== Available BIOS List ======",$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime",$List,$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","=================================",$true

        $syncHash.HPBIOSList.clear()

        $LO | ForEach-Object {
            $syncHash.HPBIOSList.add($_.Ver)
        }

        $syncHash.Control.HP_BIOS_List_Ready = $true
    } else {
        if($cred){
            Invoke-CommandAs -ComputerName $cn -Credential $cred -scriptblock $flashBios -ArgumentList $ve,$pa -AsSystem
        } else {
            Invoke-CommandAs -ComputerName $cn -scriptblock $flashBios -ArgumentList $ve,$pa -AsSystem
        }
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow","======== Computer $cn is restarting ...",$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","BIOS update in progress, please stand by ...",$true
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan","============================================",$true
    }

    $syncHash.Control.HPCMSL_scriptblock_Completed = $true
}

$syncHash.GUI.btn_HpBiosFlash.Add_Click({
    [string]$cn  = $syncHash.Gui.cb_Target.text
    [string]$ve  = $syncHash.Gui.cb_HPBIOSVersions.text
    [string]$pa  = $syncHash.Gui.pb_HpBiosAdminPsw.text
    [bool]$flash = $false

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0156]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    if($syncHash.Gui.cb_HPBIOSVersions.items.count -eq 0){
        $flash = $false
    } else {
        $flash = $true
    }

    # Disable wedgets
    $syncHash.Gui.btn_HPCMSL.IsEnabled        = $false
    $syncHash.Gui.tb_att.IsEnabled            = $false
    $syncHash.Gui.tb_val.IsEnabled            = $false
    $syncHash.Gui.btn_HpGet.IsEnabled         = $false
    $syncHash.Gui.btn_HpSet.IsEnabled         = $false
    $syncHash.Gui.pb_HpBiosAdminPsw.IsEnabled = $false
    $syncHash.Gui.pb_HpBiosSysPsw.IsEnabled   = $false
    $syncHash.Gui.btn_HpList.IsEnabled        = $false
    $syncHash.Gui.btn_HpClear.IsEnabled       = $false
    $syncHash.Gui.cb_HPBIOSVersions.IsEnabled = $false
    $syncHash.Gui.btn_HpBiosFlash.IsEnabled   = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.HpBiosFlash_scriptblock).AddArgument($cn).AddArgument($ve).AddArgument($pa).AddArgument($flash).AddArgument($syncHash.PSRemote_credential)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.MonitorInfo_scriptblock = {
    param(
        [string]$cn
    )

    $MonitorInfo = $null
    $MonitorInfo = Get-WmiObject WmiMonitorID -Namespace root\wmi -computerName $cn

    Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","===== List of Monitor(s) on $cn",$true

    $MonitorInfo | ForEach-Object {
        $Manufacturer = ($_.ManufacturerName -notmatch '^0$' | ForEach-Object {[char]$_}) -join ""
        $Name         = ($_.UserFriendlyName -notmatch '^0$' | ForEach-Object {[char]$_}) -join ""
        $Serial       = ($_.SerialNumberID   -notmatch '^0$' | ForEach-Object {[char]$_}) -join ""

        $msg = "Manufacturer "
        $msg = $msg.PadRight(13,' ') + ": "
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",  $msg,$false
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$Manufacturer,$true
        $msg = "Name "
        $msg = $msg.PadRight(13,' ') + ": "
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",  $msg,$false
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$Name,$true
        $msg = "Serial "
        $msg = $msg.PadRight(13,' ') + ": "
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Cyan",  $msg,$false
        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Yellow",$Serial,$true

        Invoke-Command $syncHash.outputFromThread_scriptblock -ArgumentList "Courier New","18","Lime","===============",$true
    }

    $syncHash.Control.MonitorInfo_scriptblock_Completed = $true
}

$syncHash.GUI.btn_Monitors.Add_Click({
    [string]$cn  = $syncHash.Gui.cb_Target.text

    if([string]::IsNullOrEmpty($cn)){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand Target is blank." -NewLine $true
        return
    }

    # Ping test
    try {
        $test = [bool](Test-Connection -Quiet -BufferSize 32 -Count 1 -ComputerName $cn 2>$null 3>$null)
    } catch {
        $e = "[Error 0157]"
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $e
        Invoke-Command $syncHash.Log_scriptblock -ArgumentList $error[0]
        return
    }

    if(!$test){
        Show-Result -Font "Courier New" -Size "18" -Color "Red" -Text "  $Global:emoji_hand The target is offline." -NewLine $true
        return
    }

    # Disable wedgets
    $syncHash.Gui.btn_Monitors.IsEnabled = $false

    # create the extra Powershell session and add the script block to execute
    $Session = [PowerShell]::Create().AddScript($syncHash.MonitorInfo_scriptblock).AddArgument($cn)

    # execute the code in this session
    $Session.RunspacePool = $RunspacePool
    $Handle = $Session.BeginInvoke()
    $syncHash.Jobs.Add([PSCustomObject]@{
        'Session' = $Session
        'Handle' = $Handle
    })

    [System.GC]::Collect()
    $syncHash.Gui.PB.IsIndeterminate = $true
})

$syncHash.GUI.btn_Credential.Add_Click({
    [pscredential]$cred = $null

    $cred = Get-Credential -Message "The credential for the target:"
    if($cred){
        $syncHash.Gui.gb_Target.header = "Target - [" + $cred.Username + "]"
    } else {
        $syncHash.Gui.gb_Target.header = "Target"
        Show-Result -Font "Courier New" -Size "18" -Color "Yellow" -Text "  $Global:emoji_hand No credential provided, default to the current user." -NewLine $true
        return
    }
    $syncHash.PSRemote_credential = $cred
})
############################################################### Finally
# Set target focused when app starts
$syncHash.Gui.cb_Target.Template.FindName("PART_EditableTextBox", $syncHash.Gui.cb_Target)

$script:bitmap = New-Object System.Windows.Media.Imaging.BitMapImage
$bitmap.BeginInit()
$bitmap.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($bee_icon)
$bitmap.EndInit()
$bitmap.Freeze()
$syncHash.window.Icon = $bitmap
# Entering main message loop
$syncHash.Window.ShowDialog() | Out-Null

<############################################################
if ($psISE)
{
    $null = $syncHash.window.Dispatcher.InvokeAsync{$syncHash.Window.ShowDialog()}.Wait()
}
Else
{
    $windowcode = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
    $asyncwindow = Add-Type -MemberDefinition $windowcode -Name Win32ShowWindowAsync -Namespace Win32Functions -PassThru
    $null = $asyncwindow::ShowWindowAsync((Get-Process -PID $pid).MainWindowHandle, 0)
 
    $app = New-Object -TypeName Windows.Application
    $app.Run($syncHash.Window)
}
#############################################################>