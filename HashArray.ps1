$HashArray = @()

$Setting1 = 'LogSetting1'
$value1 = 'Value'



$HashArray += ('Logging',@{$($Setting1)=$Value1})

$HashArray += ('Applications', @{'A1'='SettingA1';'B1'='SettingB1'})

$HashArray[0]
$HashArray[1]
