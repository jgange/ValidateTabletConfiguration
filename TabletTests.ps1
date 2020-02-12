################# Variable Initialization ####################################

$TestResults = @()
$ExecutionStart = Get-Date
$ResultsFileMode = '-Append'
$TestResultStatus = @('Test Passed','Test Failed')
$ResultFields = @('TestName','Description','Result','Message','TimeStamp')
$ResultSet = @()

# General File Path Data

$StagingFolder = 'C:\Staging\'
$ResultsFile = $StagingFolder + $env:COMPUTERNAME + '_DockAutoTests.csv'
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
$AveryScaleAppVer = $StartUpFolder + 'FLS100.lnk'


# Registry Key Values -- * indicates a replacement is going to occur such as a user name or password

$AutoLogonSetting = @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','AutoAdminLogon',1)
$AutoLogonAccount = @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','DefaultDomainName','paradise')
$AutoLogonAccount = @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','DefaultUserName','*username')
$AutoLogonAccount = @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','DefaultPassword','*password')

$ScannerPortEnabled = @('HKLM:SOFTWARE\Wow6432Node\Intermec\ADCPorts\2','State',1)




############## FUNCTION DEFINITIONS #############################################

### UTILITY FUNCTIONS ######

Function WriteResults($DataSet)
{
    $Dataset
    $Output += New-Object PSObject -Property $DataSet
    $Output | Export-Csv -NoTypeInformation -Path $ResultsFile
    $Output = $null
}


Function GetRunTime($StartTime, $FinishTime)
{
    return ($FinishTime - $StartTime).Seconds
}


Function ScheduleTestRun()
{
    # Stub
}


########## TEST FUNCTIONS ######################

Function CheckFileSystemAccess([string]$Folder, [string]$Account, [string]$AccessType)
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
    
    $DataSet = [ordered]@{'TestName'=$TestName;'Result'=$Result;'Timestamp'=$TimeStamp;'Message'=$Message;'Description'=$Description}
    WriteResults $DataSet
 
}





###################### MAIN PROGRAM ####################################################

CheckFileSystemAccess "C:\Users\a-joe.gange" "v-jgange" "FullControl"

$RunTime = GetRunTime $ExecutionStart (Get-Date)
