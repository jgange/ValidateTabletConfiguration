################# Variable Initialization ####################################

$TestResults = @()
$ExecutionStart = Get-Date
$ResultsFileMode = '-Append'
$TestResultStatus = @('Test Passed','Test Failed')
$ResultFields = @('TestName','Description','Result','Message','TimeStamp','Category')
$ResultSet = @()
$HostName = $env:COMPUTERNAME
$CurrentUser = $env:USERNAME
$LogonDomain = $env:USERDOMAIN
$LocalGroupName = 'Administrators'

# General File Path Data

$StagingFolder = 'C:\Staging\'
$ResultsFile = $StagingFolder + $HostName + '_DockAutoTests.csv'
$StartUpFolder = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\'
$Desktop = 'C:\Users\Public\Desktop\'
$SCCMClientLogs = 'C:\Windows\CCM\Logs\'

# Application Checks - version and installation

$Applications = @(@{Name='DockScanning Windows ';Version='3.4.9'},@{Name='Microsoft SQL Server Compact 3.5 SP2 x64 ENU';Version='3.5.8080.0'},@{Name='IMG My-T-Soft Basic';Version='2.30'},@{Name='Microsoft SQL Server Compact 3.5 SP2 ENU';Version='3.5.8080.0'},@{Name='RescueAssist by LogMeIn Unattended';Version='1.0.0.341'})

# Application configuration file paths

$DockScan = 'DockScanning Windows.lnk'
$AveryScale = 'FLS100.lnk'
$AveryConfigFile = '\AppData\Local\Avery_Weigh-Tronix\FLS100.exe_Url_sz0xpqf3otpq0dnrfv3sqp12zh3xs51y\1.3.9.0\user.config'
$DockScanProgram = 'C:\Program Files\DockScanning Windows Manufacturer\DockScanning Windows\'
$DockScanLogFolder = 'C:\Program Files\DockScanning Windows Manufacturer\DockScanning Windows\Logs\'
$AveryDB = 'C:\ProgramData\Avery Weigh-Tronix\FLS 100\1.3.9.0\'
$DockScanShortcut = $StartUpFolder + 'DockScanning Windows.lnk'
$AveryScaleAppShortcut = $StartUpFolder + 'FLS100.lnk'
$DockScanDesktop = $Desktop + $DockScan
$AveryDesktop = $Desktop + $AveryScale

# Registry Key Values -- * indicates a replacement is going to occur such as a user name or password

$AutoLogonSetting = @{RegPath='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';KeyName='AutoAdminLogon';KeyValue=1}
$AutoLogonDomain = @{RegPath='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';Keyname='DefaultDomainName';KeyValue='paradise'}
$AutoLogonAccount = @{RegPath='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';KeyName='DefaultUserName';KeyValue='*username'}
$AutoLogonPassword = @{RegPath='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';KeyName='DefaultPassword';KeyValue='*password'}

$ScannerPortEnabled = @{RegPath='HKLM:SOFTWARE\Wow6432Node\Intermec\ADCPorts\2';KeyName='State';KeyValue=1}

$DisableKeyAudioFeedback = @{RegPath='HKCU:Software\Microsoft\TabletTip\1.7';KeyName='EnableKeyAudioFeedback';KeyValue='0'}
$DisableAutoShiftEngage = @{RegPath='HKCU:Software\Microsoft\TabletTip\1.7';KeyName='EnableAutoShiftEngage';KeyValue='0'}
$DisableHideEdgeTabOnPenOutofRange = @{RegPath='HKCU:Software\Microsoft\TabletTip\1.7';KeyName='HideEdgeTabOnPenOutOfRange';KeyValue='0'}
$DisableTextPrediction = @{RegPath='HKCU:Software\Microsoft\TabletTip\1.7';KeyName='EnableTextPrediction';KeyValue='0'}
$DisablePredicionScapeInsertion = @{RegPath='HKCU:Software\Microsoft\TabletTip\1.7';KeyName='EnablePredictionSpaceInsertion';KeyValue='0'}
$DisableDoubleTapSpace = @{RegPath='HKCU:Software\Microsoft\TabletTip\1.7';KeyName='EnableDoubleTapSpace';KeyValue='0'}

$DisableTabletMode = @{RegPath='HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell';KeyName='Tablet Mode';KeyValue='0'}

$SetAutoUpdateOptions = @{RegPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';KeyName='AUOptions';KeyValue='2'}
$DisableAutoUpdates = @{RegPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';KeyName='NoAutoUpdate';KeyValue='1'}

$OOBEDisabled = @{RegPath='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';KeyName='EnableFirstLogonAnimation';KeyValue='0'}


# Running services

$RemoteRegistryService = 'Remote Registry'


# Account Information

$Logons = @('svc_dockatl','svc_dockchi','svc_dockchr','svc_dockcin','svc_dockclv','svc_dockcom','svc_dockdet','svc_dockdls','svc_dockopt','svc_dockhou','svc_dockind','svc_docklax','svc_docklou','svc_dockopt','svc_dockmps','svc_docknsh','svc_docksea','svc_docksfs','svc_dockstl','svc_dockstp')
$Pswds = @('hG#xh7GaS2VLLYenOdWLvgDs28BJPJ9y','B59jdq6e45V63PhpvAnEaAAUn3WFDX','gn1MjmCJVW8LY2PQDs44GsRL2wHE0t','aRCbNN7sjT2mMdaFambLL8yo5EDvZt','mweMXzfmjofPKQ7gaFP5Yc01MR7q9z','fDs=^J^)rPk@6Unth_zY0xhKc:a0Z:D6','3JAcCk8BHEcV0xodg3YykWepKGTk5q','uuWgjY={=ki3','R1853:A*feR58kH','7ubohwWsWfYy','5eo9cHsjxFf7x022RTwnQzQi2FbPqV','d!UMMn6Tb^dC','EquPh4WhwnahGCpjBcEpocsAA4n37x','R1853:A*feR58kH','WUu1zdKdgw5CXJ7cAgwQCbsogaucJC','Uhd79e6EDshKT2rjbvTFbpbTG7vYFs','r1VkNEarBzTQfJwrN1C9oj1L7Q93RJ','EDE5oTvQw5KEFtp0A0VpRWu7tgcsb9','NzhC1Ec97v1GyFMfa5rF2rxxPXWs9g','G29tCJkzdg8PbZKwYbWX5rZcag68kf')
$LocalAdminUsers = @('LAX_ADMIN','DOCK_ADMIN','MKE_ADMIN')
$Sites = @('atlt','chit','chrt','cint','clvt','comt','dett','dlst','dowt','hout','indt','laxt','lout','mket','mpst','nsht','seat','sfst','stlt','stpt')
$SiteTimeZones = @(@{SiteName='';TimeZone=''},{})


# SCCM Client

$ClientIDLogs = $SCCMClientLogs + 'ClientIDManagerStartup*.log'

# Performance

$WindowsDefenderMaxCPU = '5'

# Testing Data to override variables

$HostName = 'CHRT0003'
$UserName = 'svc_dockchr'
$TestRegistryValue = @{RegPath='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Robert';KeyName='DefaultPassword';KeyValue='*password'}
#$Applications = @(@{Name='DBeaver 5.3.5';Version='5.3.5'},@{Name='Greenshot 1.2.10.6';Version='1.2.10.6'})

############## FUNCTION DEFINITIONS #############################################

### UTILITY FUNCTIONS ######

Function Initialize()
{
    # This function sets up any necessary structures in case they are not present.
    if (!(Test-Path $StagingFolder))
    {
        New-Item -Path $StagingFolder -ItemType "directory"
    }

    # Update any run-time variables

    $Global:AveryConfigFile = 'C:\Users\' + $AutoLogonAccount["KeyValue"] + $Global:AveryConfigFile

    (get-item 'C:\Windows\ccm\Logs\ClientIDManagerStartup*').Name | ForEach-Object { $SCCMClientIDLogs += $SCCMClientLogs + $_.Name }

    $ClientIDLogs = $SCCMClientLogs | ForEach-Object {(get-item 'C:\Windows\ccm\Logs\ClientIDManagerStartup*').Name}

    
    
    
    # Other initialization code here

}       

Function WriteTestResults($DataSet)
{
    $Output += New-Object PSObject -Property $DataSet
    Export-Csv -InputObject $Output -NoTypeInformation -Append -Path $ResultsFile
    $Output = $null
}


Function GetRunTime($StartTime, $FinishTime)
{
    $ElaspedTime = ($FinishTime - $StartTime).Seconds
    Write-Host "Script run time was $($ElaspedTime) second(s)."
}


Function ScheduleTestRun()
{
    # Stub
}

Function UpdateAccountCredentials()
{
    # This function is required in order to update the default value for the username and password for the Autologon settings since they must be discovered at run time
    $SitePrefix = $HostName.Substring(0,4).ToLower()
    $SiteName = $Sites -eq $SitePrefix

    $MatchIndex = (0..($Sites.Count-1)) | where {$Sites[$_] -eq $SitePrefix}
    $UserName = $Logons[$MatchIndex]
    $PassWord = $Pswds[$MatchIndex]

    $AutoLogonAccount["KeyValue"] = $UserName
    $AutoLogonPassword["KeyValue"] = $PassWord
}

Function CheckIfFileExists([string]$FilePath, [string]$Category)
{
    If (Test-Path $FilePath)
    {
        $Result = 'Test Passed'
        $Message = 'Filepath ' + $FilePath + ' exists on the tablet.'
    }
    else
    {
        $Result = 'Test Failed'
        $Message = 'Filepath ' + $FilePath + ' was not found.'
    }

    $TestName = 'Check Existence of ' + $FilePath
    $Description = 'Checking for existence of filepath ' + $FilePath + ' on the device.'
    $TimeStamp = Get-Date
    
    $DataSet = [ordered]@{'TestName'=$TestName;'Result'=$Result;'Timestamp'=$TimeStamp;'Message'=$Message;'Description'=$Description;'Category'=$Category}
    
    WriteTestResults $DataSet

}

Function CheckFileSystemAccess([string]$Folder, [string]$Account, [string]$AccessType, [string]$Category) #Modify this to the use hash tables like the Registry entries
{
    $DataSet = @{}
    
    try
    {
        $access = (Get-Acl $Folder).Access | Where-Object {$_.IdentityReference -match $Account} | Select FileSystemRights
    }
    Catch [System.UnauthorizedAccessException]
    {
        $ErrorMsg = $_.Exception.Message + $_.Exception.ItemName
    }
    
    if ($access -match $AccessType)
    { 
        $Result = 'Test Passed'
        $Message = 'Account ' + $Account + ' has ' + $AccessType + ' access to folder ' + $Folder
    }
    else
    {
        $Result = 'Test Failed'
        if ($access -eq $null) 
        {
            $Message = $ErrorMSg + ' Account ' + $Account + ' has no access to the ' + $Folder + ' folder.'
        }
    }

    $TestName = 'Check Access to ' + $Folder
    $Description = 'Checking file permissions for account ' + $Account + ' on the ' + $Folder + ' where the expected Access level is ' + $AccessType
    $TimeStamp = Get-Date
    
    $DataSet = [ordered]@{'TestName'=$TestName;'Result'=$Result;'Timestamp'=$TimeStamp;'Message'=$Message;'Description'=$Description;'Category'=$Category}
    
    WriteTestResults $DataSet
 
}


Function CheckRegistryStatus($RegistryEntry, [string]$Category)
{
   
    $DataSet = @{}
    
    Try
    {
        $CheckKey = (Get-ItemPropertyValue -Path $RegistryEntry["RegPath"] -Name $RegistryEntry["KeyName"] -ErrorAction Stop)

        If ($CheckKey -eq $RegistryEntry["KeyValue"])
        {
            $Result = 'Test Passed'
            $Message = 'Registry key ' + $RegistryEntry["RegPath"] + '\' + $RegistryEntry["KeyName"] + ' has the proper value of ' + $RegistryEntry["KeyValue"] + '.'
        }
        Else
        {
            $Result = 'Test Failed'
            $Message = 'Registry key ' + $RegistryEntry["RegPath"] + '\' + $RegistryEntry["KeyName"] + ' has the incorrect value of ' + $CheckKey + ' instead of ' + $RegistryEntry["KeyValue"] + '.'
        }
    }
    Catch
    {
        $Result = 'Test Failed'
        $Message = $_.Exception
    }


    $TestName = 'Check value of registry key ' + $RegistryEntry["RegPath"] + '\' + $RegistryEntry["KeyName"]
    $Description = 'Checking registry key ' + $RegistryEntry["RegPath"] + '\' + $RegistryEntry["KeyName"] + ' for the value ' + $RegistryEntry["KeyValue"]
    $TimeStamp = Get-Date

    $DataSet = [ordered]@{'TestName'=$TestName;'Result'=$Result;'Timestamp'=$TimeStamp;'Message'=$Message;'Description'=$Description;'Category'=$Category}
    WriteTestResults $DataSet

}

Function CheckServiceStatus([string]$ServiceName, [string]$ExpectedStatus, [string]$Category)
{
    
    $DataSet = @{}
    
    $CurrentServiceState = (Get-Service -DisplayName $ServiceName).Status
    if ($CurrentServiceState -eq $ExpectedStatus)
    {
        $Result = 'Test Passed'
        $Message = $ServiceName + ' service is running.'
    }
    else
    {
        $Result = 'Test Failed'
        $Message = $ServiceName + ' service state is ' + $CurrentServiceState + '.'
    }

    $TestName = 'Check status of service ' + $ServiceName
    $Description = 'Checking the status of the ' + $ServiceName + ' service. It should be running.'
    $TimeStamp = Get-Date

    $DataSet = [ordered]@{'TestName'=$TestName;'Result'=$Result;'Timestamp'=$TimeStamp;'Message'=$Message;'Description'=$Description;'Category'=$Category}
    WriteTestResults $DataSet

}

Function CheckApplicationInstalled ([string] $Application, [string] $Version, [string] $Category)
{

    $DataSet = @{}

    #$test = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -match $Application } | Select-Object -Property DisplayName, DisplayVersion
    $test = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {($_.DisplayName -match $Application) -and ($_.DisplayVersion -match $Version)}
    if ($test -ne $null)
    {
        $Result = 'Test Passed'
        $Message = $test.DisplayName + ' version ' + $test.DisplayVersion + ' is installed on this system.' 
    }
    else
    {
        $Result = 'Test Failed'
        $Message = $Application + ' version ' + $Verion + ' is not installed on this system.' 
    }

    $TestName = 'Check for installation of ' + $Application
    $Description = 'Verify that version ' + $Version + ' of the ' + $Application + ' application is installed on this tablet.'
    $TimeStamp = Get-Date

    $DataSet = [ordered]@{'TestName'=$TestName;'Result'=$Result;'Timestamp'=$TimeStamp;'Message'=$Message;'Description'=$Description;'Category'=$Category}
    WriteTestResults $DataSet

}
 

########## TEST FUNCTIONS ######################

Function ValidateLoggedInUser([string] $Category)
{

    $DataSet = @{}

    if ($UserName -match $LocalAdminUsers)
    {
        $Result = 'Test Failed'
        $Message = 'A local administrator account is currently logged into this tablet.'
    }
    if ($UserName.Substring(($UserName.Length-3),3) -eq $HostName.Substring(0,3))
    {
        $Result = 'Test Passed'
        $Message = 'The account ' + $UserName + ' is currently logged into this machine with the site prefix ' + $HostName.Substring(0,3) + ' which is a match.' 
    }   
    else
    {
        $Result = 'Test Failed'
        $Message = 'The currently logged in user account on this tablet is ' + $UserName + ' which does not match the three digit site prefix from the machine name of ' + $HostName.Substring(0,3) + '.'
    }

    $TestName = 'Validate logged-in service account matches Site prefix of Tablet'
    $Description = 'The user logged into the tablet should be using a service account of the form svc_dock<site prefix> where the site prefix is the first three characters of the machine name.'
    $TimeStamp = Get-Date

    $DataSet = [ordered]@{'TestName'=$TestName;'Result'=$Result;'Timestamp'=$TimeStamp;'Message'=$Message;'Description'=$Description;'Category'=$Category}
    WriteTestResults $DataSet

}

Function ValidateAutoLoginStatus([string] $Category)
{
    CheckRegistryStatus $AutoLogonSetting "Autologon" | Out-Null
    CheckRegistryStatus $AutoLogonDomain "Autologon" | Out-Null
    CheckRegistryStatus $AutoLogonAccount "Autologon" | Out-Null
    CheckRegistryStatus $AutoLogonPassWord "Autologon" | Out-Null
}

Function IsServiceAccountLocalUser([string] $Category)
{
    $DataSet = @{}

    try
    {
        Get-LocalGroupMember -Group $LocalGroupName -Member $AutoLogonAccount["KeyValue"] -ErrorAction Stop
        $Result = 'Test Failed'
        $Message = 'The user account ' + $AutoLogonAccount["KeyValue"] + ' is a member of the ' + $LocalGroupName + ' group.'
    }
    catch [Microsoft.PowerShell.Commands.PrincipalNotFoundException]
    {
        $Result = 'Test Passed'
        $Message = 'The user account ' + $AutoLogonAccount["KeyValue"] + ' is not a member of the ' + $LocalGroupName + ' group.'
    }

    $TestName = 'Check if service account user is not a member of the local administrators group'
    $Description = 'The user logged into the tablet should not be a member of the local administrators group.'
    $TimeStamp = Get-Date

    $DataSet = [ordered]@{'TestName'=$TestName;'Result'=$Result;'Timestamp'=$TimeStamp;'Message'=$Message;'Description'=$Description;'Category'=$Category}
    WriteTestResults $DataSet

}

Function ValidateTabletApps($Applications, [string] $Category)
{
    forEach($app in $Applications)
    {
        CheckApplicationInstalled $app["Name"] $app["Version"] "Application"
    }
}


Function CheckWirelessAdapter([string] $Category)
{
 
    $DataSet = @{}

    $Interface = Get-NetAdapter | Where-Object { $_.Name -eq 'Wi-Fi'}

    if ($Interface.Status -eq 'Up')
    {
        $Result = 'Test Passed'
        $Message = 'Interface ' + $Interface.InterfaceDescription + ' is ' + $Interface.Status + '.'
    }
    else
    {
        $Result = 'Test Failed'
        $Message = 'Interface ' + $Interface.InterfaceDescription + ' is ' + $Interface.Status + '.'
    }

    $TestName = 'Check Wireless Interface status.'
    $Description = 'Check if the Wireless Interface is up.'
    $TimeStamp = Get-Date

    $DataSet = [ordered]@{'TestName'=$TestName;'Result'=$Result;'Timestamp'=$TimeStamp;'Message'=$Message;'Description'=$Description;'Category'=$Category}
    WriteTestResults $DataSet

}

Function CheckWindowsDefenderThrottle ([string] $Category)
{

    $DataSet = @{}

    $MaxCPULoad = (Get-MpPreference).ScanAvgCPULoadFactor
    If ($MaxCPULoad -eq $WindowsDefenderMaxCPU)
    {
        $Result = 'Test Passed'
        $Message = 'The Maximum CPU load for Windows Defender is set to ' + $MaxCPULoad
    }
    else
    {
        $Result = 'Test Failed'
        $Message = 'The Maximum CPU load for Windows Defender is set to ' + $MaxCPULoad + '.'
    }

    $TestName = 'Check Windows Defender Max CPU load'
    $Description = 'Check Windows Defender Max CPU load value.'
    $TimeStamp = Get-Date

    $DataSet = [ordered]@{'TestName'=$TestName;'Result'=$Result;'Timestamp'=$TimeStamp;'Message'=$Message;'Description'=$Description;'Category'=$Category}
    WriteTestResults $DataSet
}


Function CheckSCCMClientRegistration ([string] $Category)
{
 
 $DataSet = @{}

 $CheckString = "\[RegTask] - Client is registered. Exiting."
 $GetClientRegistration = Select-String -path $ClientIDLogs -Pattern $CheckString
 
  If ($GetClientRegistration)
    {
        $Result = 'Test Passed'
        $Message = 'Client is registered. ' + $GetClientRegistration
    }
    else
    {
        $Result = 'Test Failed'
        $Message = 'Client is not registered.'
    }

    $TestName = 'Check if SCCM Client is registered with the server'
    $Description = 'Check the ClientIDLog files in the SCCM client folder to see if the client has been registered with the server.'
    $TimeStamp = Get-Date

    $DataSet = [ordered]@{'TestName'=$TestName;'Result'=$Result;'Timestamp'=$TimeStamp;'Message'=$Message;'Description'=$Description;'Category'=$Category}
    WriteTestResults $DataSet

}

Function ValidateOnScreenKeyboardSettings([string] $Category)
{
    CheckRegistryStatus $DisableKeyAudioFeedback "On Screen KeyBoard" | Out-Null
    CheckRegistryStatus $DisableAutoShiftEngage "On Screen KeyBoard" | Out-Null
    CheckRegistryStatus $DisableHideEdgeTabOnPenOutofRange "On Screen KeyBoard" | Out-Null
    CheckRegistryStatus $DisableTextPrediction "On Screen KeyBoard" | Out-Null
    CheckRegistryStatus $DisablePredicionScapeInsertion "On Screen KeyBoard" | Out-Null
    CheckRegistryStatus $DisableDoubleTapSpace "On Screen KeyBoard" | Out-Null
    CheckRegistryStatus $DisableTabletMode "Tablet Display Mode" | Out-Null
}

Function AutoUpdateAndOOBEDisabled([string] $Category)
{
    CheckRegistryStatus $SetAutoUpdateOptions "Disable AutoUpdate" | Out-Null 
    CheckRegistryStatus $DisableAutoUpdates "Disable AutoUpdate" | Out-Null
    CheckRegistryStatus $OOBEDisabled "Disable OOBE" | Out-Null
}

Function CheckFirewallStatus([string] $Category)
{
    $DataSet = @{}
    $Flag = 0

    $FireWallStatus = Get-NetFirewallProfile | Select-Object Name,Enabled   
    $FireWallStatus | ForEach-Object { if ($_.Enabled -eq 'True') {$Flag++} }
    
    If ($Flag -eq 0)
    {
        $Result = 'Test Passed'
        $Message = 'Firewall is disabled for each zone.'
    }
    else
    {
        $Result = 'Test Failed'
        $Message = 'Firewall is enabled for the following zones-- ' + ($FireWallStatus | ForEach-Object {$_.Name + ':' + $_.Enabled})
    }

    $TestName = 'Check Windows Firewall Status'
    $Description = 'Checks if the Windows Firewall is enabled for any of the zones.'
    $TimeStamp = Get-Date

    $DataSet = [ordered]@{'TestName'=$TestName;'Result'=$Result;'Timestamp'=$TimeStamp;'Message'=$Message;'Description'=$Description;'Category'=$Category}
    WriteTestResults $DataSet
}



###################### MAIN PROGRAM ####################################################


UpdateAccountCredentials
Initialize

# Begin Test Run

# CheckFileSystemAccess "C:\Users\a-joe.gange" "v-jgange" "FullControl" "Application" | Out-Null

CheckFileSystemAccess $DockScanProgram $AutoLogonAccount["KeyValue"] "Modify" "Dock Scan Application" | Out-Null
CheckFileSystemAccess $DockScanLogFolder $AutoLogonAccount["KeyValue"] "Modify" "Dock Scan Application" | Out-Null
CheckFileSystemAccess $AveryDB $AutoLogonAccount["KeyValue"] "FullControl" "Avery Scale Application" | Out-Null
CheckIfFileExists $DockScanShortcut "Dock Scan Application"
CheckIfFileExists $AveryScaleAppShortcut "Avery Scale Application"
CheckIfFileExists $DockScanDesktop "Dock Scan Application"
CheckIfFileExists $AveryDesktop "Avery Scale Application"
ValidateLoggedInUser "Login Credentials"
IsServiceAccountLocalUser "Security"
ValidateAutoLoginStatus "Autologon"
CheckRegistryStatus $ScannerPortEnabled "Bar Code Scanner"
CheckIfFileExists $AveryConfigFile "Avery Scale Software"
CheckServiceStatus $RemoteRegistryService "Running" "RemoteAccess"
ValidateTabletApps $Applications "Applications"
CheckWirelessAdapter "Wireless"
CheckWindowsDefenderThrottle "Performance"
CheckRegistryStatus $OOBEDisabled "Performance"
CheckSCCMClientRegistration "SCCM Client"
ValidateOnScreenKeyboardSettings "Keyboard and Display Settings"
AutoUpdateAndOOBEDisabled "AutoUpdates and OOBE"
CheckFireWallStatus "Security Settings"

$CompletionTime = Get-Date
GetRunTime $ExecutionStart $CompletionTime