
<#
    .SYNOPSIS
        Tests if a given credential is valid. If user name and/or
        Password of the credential are not valid then an exception is thrown.

    .PARAMETER Credential
        The credential to check for validity.
#>
function Test-Credential {
    [CmdletBinding()]
    param (
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    if ($Credential)
    {
        $user = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password

        Add-Type -AssemblyName System.DirectoryServices.AccountManagement 
        $directoryServicesMachineContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
        $credentialsAreValid = $directoryServicesMachineContext.ValidateCredentials($user, $password)
                        
        $directoryServicesMachineContext.Dispose()
        $directoryServicesMachineContext = $null
                
        if (-not $credentialsAreValid)
        {
            throw 'Invalid credentials.'
        }
    }
}

<#
    Powershell mock module for Servermanager that creates a pseudo cmdlet for
    Add-WindowsFeature, Remove-WindowsFeature and Get-WindowsFeature.
    Each of these cmdlets will manipulate a global object (defined at the end of this module),
    instead of performing their original actions.  
#>

<#
    .SYNOPSIS
        Mock Add-WindowsFeature cmdlet.
#>
function Add-WindowsFeature
{
    [CmdletBinding()]
    param(

        [System.Object]
        ${Vhd},

        [switch]
        ${IncludeAllSubFeature},

        [parameter(Position = 0)]
        [System.Object]
        ${Name},

        [switch]
        ${Restart},

        [switch]
        ${IncludeManagementTools},

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [System.Object]
        ${ConfigurationFilePath},

        [Alias('Cn')]
        [System.Object]
        ${ComputerName},

        [System.Object]
        ${Source},

        [System.Object]
        ${LogPath})

    #Test-Credential $Credential

    $changeMade = $false
    $featureResult = @()
    $exitCode = 'NoChangeNeeded'

    if (-not $script:mockWindowsFeatures[$Name].Installed)
    {
        $script:mockWindowsFeatures[$Name].Installed = $true
        $changeMade = $true
        $featureResult += $Name
    }

    if ($IncludeAllSubFeature)
    {
        foreach ($subfeature in $script:mockWindowsFeatures[$Name].Subfeatures)
        {
            if (-not $script:mockWindowsFeatures[$subfeature].Installed)
            {
                $script:mockWindowsFeatures[$subfeature].Installed = $true
                $changeMade = $true
                $featureResult += $subfeature
            }
        }
    }

    if ($changeMade)
    {
        $exitCode = 'Success'
    }

    $windowsFeature = @{
        Success = $true
        RestartNeeded = 'no'
        FeatureResult = $featureResult
        ExitCode = $exitCode
    }

    $windowsFeatureObject = New-Object PSObject -Property $windowsFeature
    $windowsFeatureObject.PSTypeNames[0] = 'Microsoft.Windows.ServerManager.Commands.FeatureOperationResult'
            
    return $windowsFeatureObject
}

<#
    .SYNOPSIS
        Mock Get-WindowsFeature cmdlet.
#>
function Get-WindowsFeature
{
    [CmdletBinding()]

    param(
        [System.Object]
        ${Vhd},

        [Parameter(Mandatory = $true, Position = 1)]
        [System.Object]
        ${Name},

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [Alias('Cn')]
        [System.Object]
        ${ComputerName},


        [System.Object]
        ${LogPath}
        )

    #Test-Credential $Credential

    $windowsFeature = $script:mockWindowsFeatures[$Name]
    $windowsFeatureObject = New-Object PSObject -Property $windowsFeature
    $windowsFeatureObject.PSTypeNames[0] = 'Microsoft.Windows.ServerManager.Commands.Feature'
            
    return $windowsFeatureObject
}

<#
    .SYNOPSIS
        Mock Remove-WindowsFeature cmdlet.
#>
function Remove-WindowsFeature
{
    [CmdletBinding(DefaultParameterSetName = 'RunningComputer', SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        ${Name},

        [Parameter(ParameterSetName = 'VhdPath')]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Vhd},

        [Parameter(ParameterSetName = 'RunningComputer')]
        [switch]
        ${Restart},

        [Parameter(ParameterSetName = 'VhdPath')]
        [Parameter(ParameterSetName = 'RunningComputer')]
        [switch]
        ${IncludeManagementTools},

        [switch]
        ${Remove},

        [Alias('Cn')]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ComputerName},

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [ValidateNotNullOrEmpty()]
        [string]
        ${LogPath})

    #Test-Credential $Credential

    $changeMade = $false
    $featureResult = @()
    $exitCode = 'NoChangeNeeded'

    if ($script:mockWindowsFeatures[$Name].Installed)
    {
        $script:mockWindowsFeatures[$Name].Installed = $false
        $changeMade = $true
        $featureResult += $Name
    }

    foreach ($subfeature in $script:mockWindowsFeatures[$Name].Subfeatures)
    {
        if ($script:mockWindowsFeatures[$subfeature].Installed)
        {
            $script:mockWindowsFeatures[$subfeature].Installed = $false
            $changeMade = $true
            $featureResult += $subfeature
        }
    }
                
    if ($changeMade)
    {
        $exitCode='Success'
    }

    $windowsFeature = @{
        Success = $true
        RestartNeeded = 'no'
        FeatureResult = $featureResult
        ExitCode = $exitCode
    }

    $windowsFeatureObject =New-Object PSObject -Property $windowsFeature
    $windowsFeatureObject.PSTypeNames[0] = 'Microsoft.Windows.ServerManager.Commands.FeatureOperationResult'
            
    return $windowsFeatureObject       
}

# The following mock windows feature objects are structured the same as the output from Get-WindowsFeature.
$script:mockWindowsFeatures = @{
    Test1 = @{ 
        Name                      = 'Test1'
        DisplayName               = 'Test Feature 1'
        Description               = 'Test Feature with 3 subfeatures'
        Installed                 = $false 
        InstallState              = 'Available' 
        FeatureType               = 'Role Service'
        Path                      = 'Test1'
        Depth                     = 1
        DependsOn                 = @()
        Parent                    = ''
        ServerComponentDescriptor = 'ServerComponent_Test_Cert_Authority'
        Subfeatures               = @('SubTest1','SubTest2','SubTest3')
        SystemService             = @()
        Notification              = @()
        BestPracticesModelId      = $null
        EventQuery                = $null
        PostConfigurationNeeded   = $false
        AdditionalInfo            = @('MajorVersion', 'MinorVersion', 'NumericId', 'InstallName')
    }

    SubTest1 = @{ 
        Name                      = 'SubTest1'
        DisplayName               = 'Sub Test Feature 1'
        Description               = 'Sub Test Feature with parent as test1'
        Installed                 = $false
        InstallState              = 'Available'
        FeatureType               = 'Role Service'
        Path                      = 'Test1\SubTest1'
        Depth                     = 2
        DependsOn                 = @()
        Parent                    = 'Test1'
        ServerComponentDescriptor = $null
        Subfeatures               = @()
        SystemService             = @()
        Notification              = @()
        BestPracticesModelId      = $null
        EventQuery                = $null
        PostConfigurationNeeded   = $false
        AdditionalInfo            = @('MajorVersion', 'MinorVersion', 'NumericId', 'InstallName')
    }

    SubTest2 = @{ 
        Name                      = 'SubTest2'
        DisplayName               = 'Sub Test Feature 2'
        Description               = 'Sub Test Feature with parent as test1'
        Installed                 = $false
        InstallState              = 'Available'
        FeatureType               = 'Role Service'
        Path                      = 'Test1\SubTest2'
        Depth                     = 2
        DependsOn                 = @()
        Parent                    = 'Test1'
        ServerComponentDescriptor = $null
        Subfeatures               = @()
        SystemService             = @()
        Notification              = @()
        BestPracticesModelId      = $null
        EventQuery                = $null
        PostConfigurationNeeded   = $false
        AdditionalInfo            = @('MajorVersion', 'MinorVersion', 'NumericId', 'InstallName')
    }

    SubTest3 = @{
        Name                      = 'SubTest3'
        DisplayName               = 'Sub Test Feature 3'
        Description               = 'Sub Test Feature with parent as test1'
        Installed                 = $false
        InstallState              = 'Available'
        FeatureType               = 'Role Service'
        Path                      = 'Test\SubTest3'
        Depth                     = 2
        DependsOn                 = @()
        Parent                    = 'Test1'
        ServerComponentDescriptor = $null
        Subfeatures               = @()
        SystemService             = @()
        Notification              = @()
        BestPracticesModelId      = $null
        EventQuery                = $null
        PostConfigurationNeeded   = $false
        AdditionalInfo            = @('MajorVersion', 'MinorVersion', 'NumericId', 'InstallName')
    }
}
