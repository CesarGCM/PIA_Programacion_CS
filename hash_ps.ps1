
param(  
    [string]$TargetFolder=".\*",
    [string]$ResultFile="hash.txt"
)

(Get-ChildItem $TargetFolder | Get-FileHash | Select-Object -Property Hash, Path | Format-List | Out-File $ResultFile -Encoding ascii) 2>$null