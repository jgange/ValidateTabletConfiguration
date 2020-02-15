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

# Application Checks - version and installation

$DockScanAppVer = '3.4.9'
$AveryScaleAppVer = '1.3.9'
$RescueAssistAppVer = '1.0.0.341'
$MicrosoftSQLCompact64BitVer = '3.5.8080.0'
$MicrosoftSQLCompact32BitVer = '3.5.8080.0'
$MyTSoftAppVer = '1.90.3'

# Application configuration file paths

$AveryConfigFile = '\AppData\Local\Avery_Weigh-Tronix\FLS100.exe_Url_sz0xpqf3otpq0dnrfv3sqp12zh3xs51y\1.3.9.0\user.config'
$DockScanProgram = 'C:\Program Files\DockScanning Windows Manufacturer\DockScanning Windows\'
$DockScanLogFolder = 'C:\Program Files\DockScanning Windows Manufacturer\DockScanning Windows\Logs\'
$AveryDB = 'C:\ProgramData\Avery Weigh-Tronix\FLS 100\1.3.9.0\'
$DockScanShortcut = $StartUpFolder + 'DockScanning Windows.lnk'
$AveryScaleAppShortcut = $StartUpFolder + 'FLS100.lnk'

# Registry Key Values -- * indicates a replacement is going to occur such as a user name or password

$AutoLogonSetting = @{RegPath='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';KeyName='AutoAdminLogon';KeyValue=1}
$AutoLogonDomain = @{RegPath='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';Keyname='DefaultDomainName';KeyValue='paradise'}
$AutoLogonAccount = @{RegPath='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';KeyName='DefaultUserName';KeyValue='*username'}
$AutoLogonPassword = @{RegPath='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';KeyName='DefaultPassword';KeyValue='*password'}

$ScannerPortEnabled = @{RegPath='HKLM:SOFTWARE\Wow6432Node\Intermec\ADCPorts\2';KeyName='State';KeyValue=1}

# Running services

$RemoteRegistryService = 'Remote Registry'


# Account Information

$Logons = @('svc_dockatl','svc_dockchi','svc_dockchr','svc_dockcin','svc_dockclv','svc_dockcom','svc_dockdet','svc_dockdls','svc_dockopt','svc_dockhou','svc_dockind','svc_docklax','svc_docklou','svc_dockopt','svc_dockmps','svc_docknsh','svc_docksea','svc_docksfs','svc_dockstl','svc_dockstp')
$Pswds = @('hG#xh7GaS2VLLYenOdWLvgDs28BJPJ9y','B59jdq6e45V63PhpvAnEaAAUn3WFDX','gn1MjmCJVW8LY2PQDs44GsRL2wHE0t','aRCbNN7sjT2mMdaFambLL8yo5EDvZt','mweMXzfmjofPKQ7gaFP5Yc01MR7q9z','fDs=^J^)rPk@6Unth_zY0xhKc:a0Z:D6','3JAcCk8BHEcV0xodg3YykWepKGTk5q','uuWgjY={=ki3','R1853:A*feR58kH','7ubohwWsWfYy','5eo9cHsjxFf7x022RTwnQzQi2FbPqV','d!UMMn6Tb^dC','EquPh4WhwnahGCpjBcEpocsAA4n37x','R1853:A*feR58kH','WUu1zdKdgw5CXJ7cAgwQCbsogaucJC','Uhd79e6EDshKT2rjbvTFbpbTG7vYFs','r1VkNEarBzTQfJwrN1C9oj1L7Q93RJ','EDE5oTvQw5KEFtp0A0VpRWu7tgcsb9','NzhC1Ec97v1GyFMfa5rF2rxxPXWs9g','G29tCJkzdg8PbZKwYbWX5rZcag68kf')
$LocalAdminUsers = @('LAX_ADMIN','DOCK_ADMIN','MKE_ADMIN')
$Sites = @('atlt','chit','chrt','cint','clvt','comt','dett','dlst','dowt','hout','indt','laxt','lout','mket','mpst','nsht','seat','sfst','stlt','stpt')


# Testing Data to override variables

$HostName = 'CHRT0003'
$UserName = 'svc_dockchr'
$TestRegistryValue = @{RegPath='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Robert';KeyName='DefaultPassword';KeyValue='*password'}

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
    Write-Host "Script run time was $($ElaspedTime)"
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
        $Message = 'Account ' + $Account + ' has ' + $AccessType + ' to folder ' + $Folder
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
    $CurrentServiceState = (Get-Service -DisplayName).Status
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

########## TEST FUNCTIONS ######################

Function ValidateLoggedInUser([string] $Category)
{
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

###################### MAIN PROGRAM ####################################################


$RunTime = GetRunTime $ExecutionStart (Get-Date)

UpdateAccountCredentials
Initialize

# Begin Test Run

CheckFileSystemAccess "C:\Users\a-joe.gange" "v-jgange" "FullControl" "Application" | Out-Null
CheckIfFileExists $DockScanShortcut "Dock Scan Application"
CheckIfFileExists $AveryScaleAppShortcut "Avery Scale Application"
ValidateLoggedInUser "Login Credentials"
IsServiceAccountLocalUser "Security"
ValidateAutoLoginStatus "Autologon"
CheckRegistryStatus $ScannerPortEnabled "Bar Code Scanner"
CheckIfFileExists $AveryScaleAppShortcut "Avery Scale Software"
CheckIfFileExists $AveryConfigFile "Avery Scale Software"
CheckServiceStatus $RemoteRegistryService "Running" "RemoteAccess"

$ExecutionEnd = Get-Date
$ElaspedTime = GetRunTime $ExecutionEnd $ExecutionStart
$ElaspedTime