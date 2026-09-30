param([Parameter(Mandatory=$true)][string]$msg)

git add .
git commit -m $msg
if ($LASTEXITCODE -ne 0) { Write-Host "Commit echoue ou rien a commiter"; exit 1 }

git push
if ($LASTEXITCODE -ne 0) { Write-Host "Push echoue"; exit 1 }

ssh ubuntu@137.74.162.116 "cd ~/qraft && bash deploy.sh"