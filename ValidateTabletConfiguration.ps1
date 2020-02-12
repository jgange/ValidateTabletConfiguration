### Dock Scan Tablet Validation Script ###

# Where possible, each test will be written as a function

$TestControlFile = $PSScriptRoot +'\testconfig.cfg'

# Create hash tables to store the variable objects

$Logging = @{}
$Applications = @{}
$SiteData = @{}

Function ReadTesTConfig($TestControlFile) {

   # Parser rules- ignore blank lines, read from one set of brackets to the next for a given data set

    $config = Get-Content -Path $TestControlFile
    
    $LogConfigStart = $config.IndexOf(($config -eq "[Logging]"))

    $LogConfigStart

    $LogConfigEnd = $LogConfigStart

    Do {
        $LogConfigEnd
        $Value = $config[$LogConfigEnd]
        $CheckVal = $Value.Substring(0,1)
        $CheckVal
        $LogConfigEnd++
    } Until ($CheckVal -eq '[')

    $LogConfigEnd

}

Function WriteLogEntry() {
}

Function CheckAutoLogonAccount() {
}

Function CheckTabletKeyboardConfig () {
}

Function CheckInstalledApplicationVersion ($ApplicationName) {
  Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion
}

#### MAIN PROGRAM #####

ReadTestConfig $TestControlFile