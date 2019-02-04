function Get-IISAppCmd {
    Push-Location -Path "$env:windir\system32\inetsrv"
    $appCmd = Get-Command -Name '.\appcmd.exe' -CommandType 'Application' -ErrorAction:Stop
    Pop-Location
    $appCmd
}

function Test-IISSelfSignedModule
{
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [switch]$Enable32BitAppOnWin64
    )

    ('' -ne ((& (Get-IISAppCmd) list config -section:system.webServer/globalModules) -like "*$iisSelfSignedModuleName*"))
}

function Install-IISSelfSignedModule
{
    [CmdletBinding()]
    param (
        [switch]$Enable32BitAppOnWin64
    )

    if ($Enable32BitAppOnWin64 -eq $true)
    {
        Write-Verbose ("Install-IISSelfSignedModule: Providing $iisSelfSignedModuleAssemblyName to run in a 32 bit process")
        $sourceFilePath = Join-Path -Path "$env:windir\SysWOW64\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer" -ChildPath $iisSelfSignedModuleAssemblyName
        $destinationFolderPath = "$env:windir\SysWOW64\inetsrv"
        Copy-Item -Path $sourceFilePath -Destination $destinationFolderPath -Force
    }

    if (Test-IISSelfSignedModule)
    {
        Write-Verbose ("Install-IISSelfSignedModule: module $iisSelfSignedModuleName altready installed")
    }
    else
    {
        Write-Verbose ("Install-IISSelfSignedModule: Installing module $iisSelfSignedModuleName")
        $sourceFilePath = Join-Path -Path "$env:windir\System32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer" -ChildPath $iisSelfSignedModuleAssemblyName
        $destinationFolderPath = "$env:windir\System32\inetsrv"
        $destinationFilePath = Join-Path -Path $destinationFolderPath -ChildPath $iisSelfSignedModuleAssemblyName
        Copy-Item -Path $sourceFilePath -Destination $destinationFolderPath -Force

        & (Get-IISAppCmd) install module /name:$iisSelfSignedModuleName /image:$destinationFilePath /add:false /lock:false
    }
}

function Enable-IISSelfSignedModule
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointName,
        [switch]$Enable32BitAppOnWin64
    )

    Write-Verbose ("Enable-IISSelfSignedModule: EndpointName [$EndpointName]; Enable32BitAppOnWin64 [$Enable32BitAppOnWin64]")

    Install-IISSelfSignedModule -Enable32BitAppOnWin64:$Enable32BitAppOnWin64
    $preConditionBitnessArgumentFor32BitInstall=""
    if ($Enable32BitAppOnWin64) {
        $preConditionBitnessArgumentFor32BitInstall = "/preCondition:bitness32"
    }
    & (Get-IISAppCmd) add module /name:$iisSelfSignedModuleName /app.name:"$EndpointName/" $preConditionBitnessArgumentFor32BitInstall
}

function Disable-IISSelfSignedModule
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointName
    )
    Write-Verbose ("Disable-IISSelfSignedModule: EndpointName [$EndpointName]")

    & /(Get-IISAppCmd) delete module /name:$iisSelfSignedModuleName  /app.name:"$EndpointName/"
}

Export-ModuleMember -Function Disable-IISSelfSignedModule,Enable-IISSelfSignedModule,Test-IISSelfSignedModule
