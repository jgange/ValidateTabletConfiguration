$TestControlFile = $PSScriptRoot +'\testconfig.cfg'

$TestConfig = @()
$Headings = @()
$Indices = @()
$Config = Get-Content -Path $TestControlFile
$ConfigSettings = @()


$Headings = $Config -match '\[\w+\]'

ForEach($heading in $Headings)
{
    $Indices += $Config.IndexOf($heading)
}

$Indices += ($Config.Length -1)

# Pair up elements 0,1 1,2 2,3 3,4 until end of elements

For ($i = 0; $i -lt ($Indices.count -1); $i++)
{
    # Write-Host "$($Indices[$i]) $($Indices[$i+1])"
    # Write-Host "$($Config[$Indices[$i]])"
    $Strip = $Config[$Indices[$i]].Trim("[","]")
    #Write-Host $Strip
    for ($j=$Indices[$i]+1; $j -lt $Indices[$i+1]; $j++)
    { 
        # Write-Host $j
        if($Config[$j] -ne '') 
        {
            # Write-Host $Config[$j]
            $HashVal = $Config[$j].split(";")
            #$HashVal
            Write-Host "Adding Element $($Strip) to array with key-value pair $($HashVal[0]) and $($HashVal[1])"
            $ConfigSettings += ($Strip, @{$($HashVal[0])=$HashVal[1]})

        }
    }
}

Write-Host ("")

$ConfigSettings