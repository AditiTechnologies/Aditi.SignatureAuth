param(
    [string]$slnPath=".\src",
    [string]$projPath,
    [string]$branch,
    [string]$buildCounter,
    [string]$rev,
    [string]$nugetFolder = "C:\NugetFeed",
    [Switch]$cleanNugetFolder
)
$scriptFolder=$myInvocation.MyCommand.Path | Split-Path -parent
. "$scriptFolder\VersioningFns.ps1"

TC-message starting, $slnPath, $projPath

Function PublishToFolder
{
    param(
        [string]$path
        )
    if ($cleanNugetFolder -and $(Test-Path $nugetFolder)) {rm -r $nugetFolder}
    if (-Not (Test-Path $nugetFolder)) {md $nugetFolder -Force }

    TC-message "publishing $(ls *.nupkg) to $nugetFolder" 
    mv *.nupkg $nugetFolder -Force
}

Function NugetPack 
{
    param ([string] $path=".")
    write-host "In NugetPack: $path"
    $origLoc = get-location
    Set-Location $path
    $packageVer=$(Get-Semver -path $path -branch $branch -buildCounter $buildCounter -rev $rev -nugetCompatible )
    $params="pack", (ls *.csproj), "-Version", $packageVer,"-Exclude", "version.txt","-IncludeReferencedProjects", "-Properties", "release=$packageVer"
    TC-message $params
    (& $nuget $params)
    Set-Location -Path $origLoc
}

$nuget=(ls "$slnPath\.nuget\Nuget.exe")

$origLoc=get-location
if ($projPath -eq "") {$path = "$slnPath"} else {$path = "$projPath"}
gci *.csproj -Path $path  -Recurse |
    Select-Object Directory |
    where {test-path "$($_.Directory.FullName)\*.nuspec"} |
    ForEach-Object {
    	Set-Location $_.Directory
        NugetPack -path $_.Directory	
        PublishToFolder $nugetFolder
    	}
Set-Location -Path $origLoc
