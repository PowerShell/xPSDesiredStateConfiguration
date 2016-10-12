data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData @'
SetTargetResourceInstallwhatIfMessage=Trying to install feature {0}
SetTargetResourceUnInstallwhatIfMessage=Trying to Uninstall feature {0}
FeatureNotFoundError=The requested feature {0} is not found on the target machine.
FeatureDiscoveryFailureError=Failure to get the requested feature {0} information from the target machine. Wildcard pattern is not supported in the feature name.
FeatureInstallationFailureError=Failure to successfully install the feature {0} .
FeatureUnInstallationFailureError=Failure to successfully Unintstall the feature {0} .
QueryFeature=Querying for feature {0} using Server Manager cmdlet Get-WindowsFeature.
InstallFeature=Trying to install feature {0} using Server Manager cmdlet Add-WindowsFeature.
UninstallFeature=Trying to Uninstall feature {0} using Server Manager cmdlet Remove-WindowsFeature.
RestartNeeded=The Target machine needs to be restarted.
GetTargetResourceStartVerboseMessage=Begin executing Get functionality on the {0} feature.
GetTargetResourceEndVerboseMessage=End executing Get functionality on the {0} feature.
SetTargetResourceStartVerboseMessage=Begin executing Set functionality on the {0} feature.
SetTargetResourceEndVerboseMessage=End executing Set functionality on the {0} feature.
TestTargetResourceStartVerboseMessage=Begin executing Test functionality on the {0} feature.
TestTargetResourceEndVerboseMessage=End executing Test functionality on the {0} feature.
ServerManagerModuleNotFoundDebugMessage=ServerManager module is not installed on the machine.
SkuNotSupported=Installing roles and features using PowerShell Desired State Configuration is supported only on Server SKU's. It is not supported on Client SKU.
SourcePropertyNotSupportedDebugMessage=Source property in MSFT_RoleResource is not supported on this operating system and it was ignored.
EnableServerManagerPSHCmdletsFeature=Windows Server 2008R2 Core operating system detected: ServerManager-PSH-Cmdlets feature has been enabled.
UninstallSuccess=Successfully uninstalled the feature {0}.
InstallSuccess=Successfully installed the feature {0}.
'@
}

# Commented-out until more languages are supported
# Import-LocalizedData  LocalizedData -filename MSFT_xWindowsFeature.strings.psd1

# The Get-TargetResource cmdlet is used to fetch the status of role or feature on the target machine.
# It gives the feature info of the requested role/feature on the target machine.
function Get-TargetResource
{
     [OutputType([Hashtable])]
     param
     (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name,
        
        [System.Management.Automation.PSCredential]
        $Credential
     )

        $getTargetResourceResult = $null;

        $getTargetResourceStartVerboseMessage = $($LocalizedData.GetTargetResourceStartVerboseMessage) -f ${Name} ;
        Write-Debug -Message $getTargetResourceStartVerboseMessage;

        ValidatePrerequisites ;

        $qyeryFeatureMessage = $($LocalizedData.QueryFeature) -f ${Name} ;
        Write-Debug -Message $qyeryFeatureMessage;

        $isR2Sp1 = IsWinServer2008R2SP1;
        if($isR2Sp1 -and $psboundparameters.ContainsKey("Credential"))
        {
            $parameters = $psboundparameters.Remove("Credential");
            $feature = Invoke-Command -ScriptBlock { Get-WindowsFeature @using:psboundparameters } -ComputerName . -Credential $Credential -ErrorVariable ev
            $psboundparameters.Add("Credential", $Credential);
        }
        else
        {
            $feature = Get-WindowsFeature @psboundparameters -ErrorVariable ev
        }

        if($null -eq $ev -or $ev.Count -eq 0)
        {
            $foundError = $false;

            ValidateFeature $feature $Name;

            # If a feature does not contain SubFeature then $includeAllSubFeature would be set to $false.
            # If a feature contains one or more subfeatures then $includeAllSubFeature would be set to
            # $true only if all the subfeatures are installed, or else $includeAllSubFeature would be set to $false.
            $includeAllSubFeature = $true;

            if($feature.SubFeatures.Count -eq 0)
            {
                $includeAllSubFeature = $false;
            }
            else
            {
                foreach($currentSubFeature in $feature.SubFeatures)
                {
                   if($foundError -eq $false)
                   {
                        $parameters = $psboundparameters.Remove("Name");
                        $psboundparameters.Add("Name", $currentSubFeature);

                        $isR2Sp1 = IsWinServer2008R2SP1;
                        if($isR2Sp1 -and $psboundparameters.ContainsKey("Credential"))
                        {
                            $parameters = $psboundparameters.Remove("Credential");
                            $subFeature = Invoke-Command -ScriptBlock { Get-WindowsFeature @using:psboundparameters } -ComputerName . -Credential $Credential -ErrorVariable errorVar
                            $psboundparameters.Add("Credential", $Credential);
                        }
                        else
                        {
                            $subFeature = Get-WindowsFeature @psboundparameters -ErrorVariable errorVar
                        }

                        if($null -eq $errorVar -or $errorVar.Count -eq 0)
                        {
                            ValidateFeature $subFeature $currentSubFeature;

                            if(!$subFeature.Installed)
                            {
                                $includeAllSubFeature = $false;
                                break;
                            }
                        }
                        else
                        {
                            $foundError = $true;;
                        }
                    }
                }
            }

            if($foundError -eq $false)
            {
                if($feature.Installed)
                {
                    $ensureResult = "Present";
                }
                else
                {
                    $ensureResult = "Absent";
                }

                # Add all feature properties to the hash table
                $getTargetResourceResult = @{
                                                Name = $Name;
                                                DisplayName = $feature.DisplayName;
                                                Ensure = $ensureResult;
                                                IncludeAllSubFeature = $includeAllSubFeature;
                                            }

                $getTargetResourceEndVerboseMessage = $($LocalizedData.GetTargetResourceEndVerboseMessage) -f ${Name} ;
                Write-Debug -Message $getTargetResourceEndVerboseMessage;

                $getTargetResourceResult;
            }
        }
}


# The Set-TargetResource cmdlet is used to install or uninstall a role on the target machine.
# It also supports installing & uninstalling the role or feature specific subfeatures.
function Set-TargetResource
{
    [CmdletBinding(SupportsShouldProcess=$true, DefaultParameterSetName = "FeatureName")]

     param
     (
        [parameter(Mandatory=$true, ParameterSetName = "FeatureName")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name,

        [parameter()]
        [ValidateSet("Present", "Absent")]
        [string]
        $Ensure = "Present",

        [parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Source,

        [System.Boolean]
        $IncludeAllSubFeature = $false,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [ValidateNotNullOrEmpty()]
        [string]
        $LogPath
     )

    $getTargetResourceResult = $null;

    $inputParameter = $null;

    $setTargetResourceStartVerboseMessage = $($LocalizedData.SetTargetResourceStartVerboseMessage) -f ${Name} ;
    Write-Debug -Message $setTargetResourceStartVerboseMessage;

    ValidatePrerequisites ;

    # -Source Parameter is not applicable to Windows Server 2008 R2 SP1. Hence removing it.
    # all role/feature spcific binaries are avaliable inboc on Windows Server 2008 R2 SP1, hence
    # -Source is not supported on Windows Server 2008 R2 SP1.
    $isR2Sp1 = IsWinServer2008R2SP1;
    if($isR2Sp1 -and $psboundparameters.ContainsKey("Source"))
    {
        $sourcePropertyNotSupportedDebugMessage = $($LocalizedData.SourcePropertyNotSupportedDebugMessage) ;
        Write-Debug -Message $sourcePropertyNotSupportedDebugMessage;

        $parameters = $psboundparameters.Remove("Source");
    }


    if($Ensure -eq "Present")
    {
        $parameters = $psboundparameters.Remove("Ensure");

        $installFeatureMessage = $($LocalizedData.InstallFeature) -f ${Name} ;
        Write-Debug -Message $installFeatureMessage;

        $isR2Sp1 = IsWinServer2008R2SP1;
        if($isR2Sp1 -and $psboundparameters.ContainsKey("Credential"))
        {
            $parameters = $psboundparameters.Remove("Credential");
            $feature = Invoke-Command -ScriptBlock { Add-WindowsFeature @using:psboundparameters } -ComputerName . -Credential $Credential -ErrorVariable ev
            $psboundparameters.Add("Credential", $Credential);
        }
        else
        {
            $feature = Add-WindowsFeature @psboundparameters -ErrorVariable ev
        }

        if($feature -ne $null -and $feature.Success -eq $true)
        {
            Write-Verbose ($LocalizedData.InstallSuccess -f $Name)

            # Check if reboot is required, if so notify CA.
            if($feature.RestartNeeded -eq "Yes")
            {
                $restartNeededMessage = $($LocalizedData.RestartNeeded);
                Write-Verbose -Message $restartNeededMessage;

                $global:DSCMachineStatus = 1;
            }
        }
        else
        {
            # Add-WindowsFeature cmdlet falied to successfully install the requested feature.
            # If there are errors from the Add-WindowsFeature cmdlet. We surface those errors.
            # If Add-WindwosFeature cmdlet does not surface any errors. Then the provider throws a
            # terminating error.
            if($null -eq $ev -or $ev.Count -eq 0)
            {
                $errorId = "FeatureInstallationFailure";
                $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidOperation;
                $errorMessage = $($LocalizedData.FeatureInstallationFailureError) -f ${Name} ;
                $exception = New-Object System.InvalidOperationException $errorMessage ;
                $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $null

                $PSCmdlet.ThrowTerminatingError($errorRecord);
            }
        }
    }
    else
    {
        $parameters = $psboundparameters.Remove("Ensure");
        $parameters = $psboundparameters.Remove("IncludeAllSubFeature");
        $parameters = $psboundparameters.Remove("Source");

        $uninstallFeatureMessage = $($LocalizedData.UninstallFeature) -f ${Name} ;
        Write-Debug -Message $uninstallFeatureMessage;

        $isR2Sp1 = IsWinServer2008R2SP1;
        if($isR2Sp1 -and $psboundparameters.ContainsKey("Credential"))
        {
            $parameters = $psboundparameters.Remove("Credential");
            $feature = Invoke-Command -ScriptBlock { Remove-WindowsFeature @using:psboundparameters } -ComputerName . -Credential $Credential -ErrorVariable ev
            $psboundparameters.Add("Credential", $Credential);
        }
        else
        {
            $feature = Remove-WindowsFeature @psboundparameters -ErrorVariable ev
        }

        if($feature -ne $null -and $feature.Success -eq $true)
        {
            Write-Verbose ($LocalizedData.UninstallSuccess -f $Name)

            # Check if reboot is required, if so notify CA.
            if($feature.RestartNeeded -eq "Yes")
            {
                $restartNeededMessage = $($LocalizedData.RestartNeeded);
                Write-Verbose -Message $restartNeededMessage;

                $global:DSCMachineStatus = 1;
            }
        }
        else
        {
            # Remove-WindowsFeature cmdlet falied to successfully Uninstall the requested feature.
            # If there are errors from the Remove-WindowsFeature cmdlet. We surface those errors.
            # If Remove-WindwosFeature cmdlet does not surface any errors. Then the provider throws a
            # terminating error.
            if($null -eq $ev -or $ev.Count -eq 0)
            {
                $errorId = "FeatureUnInstallationFailure";
                $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidOperation;
                $errorMessage = $($LocalizedData.FeatureUnInstallationFailureError) -f ${Name} ;
                $exception = New-Object System.InvalidOperationException $errorMessage ;
                $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $null

                $PSCmdlet.ThrowTerminatingError($errorRecord);
            }
        }
    }

    $setTargetResourceEndVerboseMessage = $($LocalizedData.SetTargetResourceEndVerboseMessage) -f ${Name} ;
    Write-Debug -Message $setTargetResourceEndVerboseMessage;
}

# The Test-TargetResource cmdlet is used to validate if the role or feature is in a state as expected in the instance document.
function Test-TargetResource
{
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name,

        [parameter()]
        [ValidateSet("Present", "Absent")]
        [string]
        $Ensure = "Present",

        [parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Source,

        [System.Boolean]
        $IncludeAllSubFeature = $false,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [ValidateNotNullOrEmpty()]
        [string]
        $LogPath

    )

        $testTargetResourceStartVerboseMessage = $($LocalizedData.TestTargetResourceStartVerboseMessage) -f ${Name} ;
        Write-Debug -Message $testTargetResourceStartVerboseMessage;

        ValidatePrerequisites ;

        $testTargetResourceResult = $false;

        $parameters = $psboundparameters.Remove("Ensure");
        $parameters = $psboundparameters.Remove("IncludeAllSubFeature");
        $parameters = $psboundparameters.Remove("Source");

        $qyeryFeatureMessage = $($LocalizedData.QueryFeature) -f ${Name} ;
        Write-Debug -Message $qyeryFeatureMessage;

        $isR2Sp1 = IsWinServer2008R2SP1;
        if($isR2Sp1 -and $psboundparameters.ContainsKey("Credential"))
        {
            $parameters = $psboundparameters.Remove("Credential");
            $feature = Invoke-Command -ScriptBlock { Get-WindowsFeature @using:psboundparameters } -ComputerName . -Credential $Credential -ErrorVariable ev
            $psboundparameters.Add("Credential", $Credential);
        }
        else
        {
            $feature = Get-WindowsFeature @psboundparameters -ErrorVariable ev
        }


        if($null -eq $ev -or $ev.Count -eq 0)
        {
            ValidateFeature $feature $Name;


            # Check if the feature is in the requested Ensure state.
            # If so then check if then check if the subfeature is in the requested Ensure state.
            if(($Ensure -eq "Present" -and $feature.Installed -eq $true) -or
                ($Ensure -eq "Absent" -and $feature.Installed -eq $false))
            {
                $testTargetResourceResult = $true;

                # IncludeAllSubFeature is set to $true, so we need to make
                # sure that all Sub Features are alsi installed.
                if($IncludeAllSubFeature)
                {

                    foreach($currentSubFeature in $feature.SubFeatures)
                    {
                        $parameters = $psboundparameters.Remove("Name");
                        $parameters = $psboundparameters.Remove("Ensure");
                        $parameters = $psboundparameters.Remove("IncludeAllSubFeature");
                        $parameters = $psboundparameters.Remove("Source");
                        $psboundparameters.Add("Name", $currentSubFeature);

                        $isR2Sp1 = IsWinServer2008R2SP1;
                        if($isR2Sp1 -and $psboundparameters.ContainsKey("Credential"))
                        {
                            $parameters = $psboundparameters.Remove("Credential");
                            $subFeature = Invoke-Command -ScriptBlock { Get-WindowsFeature @using:psboundparameters } -ComputerName . -Credential $Credential -ErrorVariable errorVar
                            $psboundparameters.Add("Credential", $Credential);
                        }
                        else
                        {
                            $subFeature = Get-WindowsFeature @psboundparameters -ErrorVariable errorVar
                        }


                        if($null -eq $errorVar -or $errorVar.Count -eq 0)
                        {
                            ValidateFeature $subFeature $currentSubFeature;

                            if(!$subFeature.Installed)
                            {
                                $testTargetResourceResult = $false;
                                break;
                            }
                        }
                    }
                }
            }

            $testTargetResourceEndVerboseMessage = $($LocalizedData.TestTargetResourceEndVerboseMessage) -f ${Name} ;
            Write-Debug -Message $testTargetResourceEndVerboseMessage;

            $testTargetResourceResult;
        }
}


# ValidateFeature is a helper function used to validate the results of SM+ cmdlets
# Get-Windowsfeature for the user supplied feature name.
function ValidateFeature
{
    param
    (
        [object] $feature,

        [string] $Name
    )

    if($null -eq $feature)
    {
        $errorId = "FeatureNotFound";
        $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidOperation
        $errorMessage = $($LocalizedData.FeatureNotFoundError) -f ${Name}
        $exception = New-Object System.InvalidOperationException $errorMessage
        $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $null

        $PSCmdlet.ThrowTerminatingError($errorRecord);
    }

    # WildCard pattern is not supported by the role provider.
    # Hence we restrict user to request only one feature information in a single request.
    if($feature.Count -gt 1)
    {
        $errorId = "FeatureDiscoveryFailure";
        $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidResult
        $errorMessage = $($LocalizedData.FeatureDiscoveryFailureError) -f ${Name}
        $exception = New-Object System.InvalidOperationException $errorMessage
        $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $null

        $PSCmdlet.ThrowTerminatingError($errorRecord);
    }
}

# ValidatePrerequisites is a helper function used to validate if the MSFT_RoleResource is supported on the target machine.
# MSFT_RoleResource is supported only on Server SKU's. MSFT_RoleResource depend on ServerManagerModule which is avaliable
# only on Server SKU's.
function ValidatePrerequisites
{
    param
    (
    )

    #Enable ServerManager-PSH-Cmdlets feature if os is WS2008R2 Core.
    $datacenterServerCore = 12
    $standardServerCore = 13
    $EnterpriseServerCore = 14

    $operatingSystem = Get-WmiObject -Class Win32_operatingsystem
    if($operatingSystem.Version.StartsWith('6.1.') -and
        (($operatingSystem.OperatingSystemSKU -eq $datacenterServerCore) -or ($operatingSystem.OperatingSystemSKU -eq $standardServerCore) -or ($operatingSystem.OperatingSystemSKU -eq $EnterpriseServerCore)))
    {
        Write-Verbose -Message $($LocalizedData.EnableServerManagerPSHCmdletsFeature)

        # Update:ServerManager-PSH-Cmdlets has a depndency on Powershell 2 update: MicrosoftWindowsPowerShell
        # Hence enabling MicrosoftWindowsPowerShell.
        dism /online /enable-feature /FeatureName:MicrosoftWindowsPowerShell | Out-Null
        dism /online /enable-feature /FeatureName:ServerManager-PSH-Cmdlets | Out-Null
    }

    if(Import-Module ServerManager -PassThru -Verbose:$false -ErrorAction Ignore)
    {
    }
    else
    {

        $serverManagerModuleNotFoundDebugMessage = $($LocalizedData.ServerManagerModuleNotFoundDebugMessage);
        Write-Debug -Message $serverManagerModuleNotFoundDebugMessage;

        $errorId = "SkuNotSupported";
        $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidOperation
        $errorMessage = $($LocalizedData.SkuNotSupported)
        $exception = New-Object System.InvalidOperationException $errorMessage
        $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $null

        $PSCmdlet.ThrowTerminatingError($errorRecord);
    }
}


# IsWinServer2008R2SP1 is a helper function to detect if the target machine is a Win 2008 R2 SP1.
function IsWinServer2008R2SP1
{
    param
    (
    )

    # We are already checking for the Presence of ServerManager module before using this helper function.
    # Hence checking for the version shoudl be good enough to confirm that the target machine is
    # Windows Server 2008 R2 machine.
    if([Environment]::OSVersion.Version.ToString().Contains("6.1."))
    {
        return $true;
    }

    return $false;
}

Export-ModuleMember -function Get-TargetResource, Set-TargetResource, Test-TargetResource
