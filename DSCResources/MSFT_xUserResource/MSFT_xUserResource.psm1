[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')] # To be removed when username/password changed to a credential
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSDSCUseVerboseMessageInDSCResource', '')] # Write-Verbose Used in helper functions
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')] # Should process is called in a helper functions but not directly in Set-TargetResource
param ()

# A global variable that contains localized messages.
data LocalizedData
{
    # culture='en-US'
    ConvertFrom-StringData @'
    UserWithName = User: {0}
    RemoveOperation = Remove
    AddOperation = Add
    SetOperation = Set
    ConfigurationStarted = Configuration of user {0} started.
    ConfigurationCompleted = Configuration of user {0} completed successfully.
    UserCreated = User {0} created successfully.
    UserUpdated = User {0} properties updated successfully.
    UserRemoved = User {0} removed successfully.
    NoConfigurationRequired = User {0} exists on this node with the desired properties. No action required.
    NoConfigurationRequiredUserDoesNotExist = User {0} does not exist on this node. No action required.
    InvalidUserName = The name {0} cannot be used. Names may not consist entirely of periods and/or spaces, or contain these characters: {1}
    UserExists = A user with the name {0} exists.
    UserDoesNotExist = A user with the name {0} does not exist.
    PropertyMismatch = The value of the {0} property is expected to be {1} but it is {2}.
    PasswordPropertyMismatch = The value of the {0} property does not match.
    AllUserPropertisMatch = All {0} {1} properties match.
    ConnectionError = There could be a possible connection error while trying to use the System.DirectoryServices API's.
    MultipleMatches = There could be a possible multiple matches exception while trying to use the System.DirectoryServices API's.
'@
}

# Commented-out until more languages are supported
# Import-LocalizedData LocalizedData -FileName MSFT_xUserResource.strings.psd1

Import-Module "$PSScriptRoot\..\CommonResourceHelper.psm1"

if (-not (Test-IsNanoServer))
{
    Add-Type -AssemblyName 'System.DirectoryServices.AccountManagement'
}

<#
    .SYNOPSIS
        The Get-TargetResource cmdlet.
#>
function Get-TargetResource
{
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName
    )

    if (Test-IsNanoServer)
    {
        Get-TargetResourceOnNanoServer @PSBoundParameters
    }
    else
    {
        Get-TargetResourceOnFullSKU @PSBoundParameters
    }
}

<#
    .SYNOPSIS
        The Set-TargetResource cmdlet.
#>
function Set-TargetResource
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName,

        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [System.String]
        $FullName,

        [System.String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Password,

        [System.Boolean]
        $Disabled,

        [System.Boolean]
        $PasswordNeverExpires,

        [System.Boolean]
        $PasswordChangeRequired,

        [System.Boolean]
        $PasswordChangeNotAllowed
    )

    if (Test-IsNanoServer)
    {
        Set-TargetResourceOnNanoServer @PSBoundParameters
    }
    else
    {
        Set-TargetResourceOnFullSKU @PSBoundParameters
    }
}

<#
    .SYNOPSIS
        The Test-TargetResource cmdlet is used to validate if the resource
        is in a state as expected in the instance document.
    .NOTES
        There's no easy way to check whether the PasswordChangeRequired is set
        to true or false, so this value is not tested here
#>
function Test-TargetResource
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName,

        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [System.String]
        $FullName,

        [System.String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Password,

        [System.Boolean]
        $Disabled,

        [System.Boolean]
        $PasswordNeverExpires,

        [System.Boolean]
        $PasswordChangeRequired,

        [System.Boolean]
        $PasswordChangeNotAllowed
    )

    if (Test-IsNanoServer)
    {
        Test-TargetResourceOnNanoServer @PSBoundParameters
    }
    else
    {
        Test-TargetResourceOnFullSKU @PSBoundParameters
    }
}


<#
    .SYNOPSIS
        The Get-TargetResource cmdlet on a full server.
#>
function Get-TargetResourceOnFullSKU
{
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName
    )

    Set-StrictMode -Version Latest

    Assert-UserNameValid -UserName $UserName

    # Try to find a user by a name.
    $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Machine)

    try
    {
        Write-Verbose -Message 'Starting Get-TargetResource on FullSKU'
        $user = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($principalContext, $UserName);
        if ($user -ne $null)
        {
            # The user is found. Return all user properties and Ensure='Present'.
            $returnValue = @{
                                UserName = $user.Name;
                                Ensure = 'Present';
                                FullName = $user.DisplayName;
                                Description = $user.Description;
                                Disabled = -not $user.Enabled;
                                PasswordNeverExpires = $user.PasswordNeverExpires;
                                PasswordChangeRequired = $null;
                                PasswordChangeNotAllowed = $user.UserCannotChangePassword;
                            }

            return $returnValue;
        }

        # The user is not found. Return Ensure = Absent.
        return @{
                    UserName = $UserName;
                    Ensure = 'Absent';
                }
    }
    catch
    {
         New-ExceptionDueToDirectoryServicesError -ErrorId 'MultipleMatches' -ErrorMessage ($LocalizedData.MultipleMatches + $_)
    }
    finally
    {
        if ($null -ne $user)
        {
            $user.Dispose();
        }

        $principalContext.Dispose();
    }
}

<#
    .SYNOPSIS
        The Set-TargetResource cmdlet on a full server.
    .NOTES
        $Password is required if $Ensure is set to 'Present'
#>
function Set-TargetResourceOnFullSKU
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName,

        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [System.String]
        $FullName,

        [System.String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Password,

        [System.Boolean]
        $Disabled,

        [System.Boolean]
        $PasswordNeverExpires,

        [System.Boolean]
        $PasswordChangeRequired,

        [System.Boolean]
        $PasswordChangeNotAllowed
    )

    Set-StrictMode -Version Latest

    Write-Verbose -Message ($LocalizedData.ConfigurationStarted -f $UserName)

    Assert-UserNameValid -UserName $UserName


    # Try to find a user by name.
    $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Machine)

    try
    {
        $user = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($principalContext, $UserName);
        if ($Ensure -eq 'Present')
        {
            # Ensure is set to 'Present'.

            $whatIfShouldProcess = $true;
            $userExists = $false;
            $saveChanges = $false;

            if ($user -eq $null)
            {
                # A user does not exist. Check WhatIf for adding a user.
                $whatIfShouldProcess = $pscmdlet.ShouldProcess($LocalizedData.UserWithName -f $UserName, $LocalizedData.AddOperation);
            }
            else
            {
                # A user exists.
                $userExists = $true;

                # Check WhatIf for setting a user.
                $whatIfShouldProcess = $pscmdlet.ShouldProcess($LocalizedData.UserWithName -f $UserName, $LocalizedData.SetOperation);
            }

            if ($whatIfShouldProcess)
            {
                if (-not $userExists)
                {
                    # The user with the provided name does not exist. Add a new user.
                    $user = New-Object System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList $principalContext
                    $user.Name = $UserName;
                    $saveChanges = $true;
                }

                # Set user properties.
                if ($PSBoundParameters.ContainsKey('FullName') -and (-not $userExists -or $FullName -ne $user.DisplayName))
                {
                    $user.DisplayName = $FullName;
                    $saveChanges = $true;
                }
                else
                {
                    if (-not $userExists)
                    {
                        # For a newly created user, set the DisplayName property to an empty string. By default DisplayName is set to user's name.
                        $user.DisplayName = [String]::Empty;
                    }
                }

                if ($PSBoundParameters.ContainsKey('Description') -and (-not $userExists -or $Description -ne $user.Description))
                {
                    $user.Description = $Description;
                    $saveChanges = $true;
                }

                # Password. Set the password regardless of the state of the user.
                if ($PSBoundParameters.ContainsKey('Password'))
                {
                    $user.SetPassword($Password.GetNetworkCredential().Password);
                    $saveChanges = $true;
                }

                if ($PSBoundParameters.ContainsKey('Disabled') -and ((-not $userExists) -or ($Disabled -eq $user.Enabled)))
                {
                    $user.Enabled = -not $Disabled;
                    $saveChanges = $true;
                }

                if ($PSBoundParameters.ContainsKey('PasswordNeverExpires') -and (-not $userExists -or $PasswordNeverExpires -ne $user.PasswordNeverExpires))
                {
                    $user.PasswordNeverExpires = $PasswordNeverExpires;
                    $saveChanges = $true;
                }

                if ($PSBoundParameters.ContainsKey('PasswordChangeRequired'))
                {
                    if ($PasswordChangeRequired)
                    {
                        # Expire the password. This will force the user to change the password at the next logon.
                        $user.ExpirePasswordNow();
                        $saveChanges = $true;
                    }
                }

                if ($PSBoundParameters.ContainsKey('PasswordChangeNotAllowed') -and (-not $userExists -or $PasswordChangeNotAllowed -ne $user.UserCannotChangePassword))
                {
                    $user.UserCannotChangePassword = $PasswordChangeNotAllowed;
                    $saveChanges = $true;

                }

                if ($saveChanges)
                {
                    $user.Save();

                    # Send an operation success verbose message.
                    if ($userExists)
                    {
                        Write-Verbose -Message ($LocalizedData.UserUpdated -f $UserName)
                    }
                    else
                    {
                        Write-Verbose -Message ($LocalizedData.UserCreated -f $UserName)
                    }
                }
                else
                {
                    Write-Verbose -Message ($LocalizedData.NoConfigurationRequired -f $UserName)
                }
            }
        }
        else
        {
            # Ensure is set to 'Absent'.
            if ($user -ne $null)
            {
                # The user exists.
                if ($pscmdlet.ShouldProcess($LocalizedData.UserWithName -f $UserName, $LocalizedData.RemoveOperation))
                {
                    # Remove the user by the provided name.
                    $user.Delete();
                }

                Write-Verbose -Message ($LocalizedData.UserRemoved -f $UserName)
            }
            else
            {
                Write-Verbose -Message ($LocalizedData.NoConfigurationRequiredUserDoesNotExist -f $UserName)
            }
        }
    }
    catch
    {
         New-ExceptionDueToDirectoryServicesError -ErrorId 'MultipleMatches' -ErrorMessage ($LocalizedData.MultipleMatches + $_)
    }
    finally
    {
        if ($null -ne $user)
        {
            $user.Dispose();
        }

        $principalContext.Dispose();
    }

    Write-Verbose -Message ($LocalizedData.ConfigurationCompleted -f $UserName)
}

<#
    .SYNOPSIS
        The Test-TargetResource cmdlet on a full server.
    .NOTES
        There's no easy way to check whether the PasswordChangeRequired is set
        to true or false, so this value is not tested here
#>
function Test-TargetResourceOnFullSKU
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName,

        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [System.String]
        $FullName,

        [System.String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Password,

        [System.Boolean]
        $Disabled,

        [System.Boolean]
        $PasswordNeverExpires,

        [System.Boolean]
        $PasswordChangeRequired,

        [System.Boolean]
        $PasswordChangeNotAllowed
    )

    Set-StrictMode -Version Latest

    Assert-UserNameValid -UserName $UserName

    # Try to find a user by a name.
    $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Machine)

    try
    {
        $user = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($principalContext, $UserName);
        if ($user -eq $null)
        {
            # A user with the provided name does not exist.
            Write-Verbose -Message ($LocalizedData.UserDoesNotExist -f $UserName)

            if ($Ensure -eq 'Absent')
            {
                return $true;
            }
            else
            {
                return $false;
            }
        }

        # A user with the provided name exists.
        Write-Verbose -Message ($LocalizedData.UserExists -f $UserName)

        # Validate separate properties.
        if ($Ensure -eq 'Absent')
        {
            Write-Verbose -Message ($LocalizedData.PropertyMismatch -f 'Ensure', 'Absent', 'Present')
            return $false; # The Ensure property does not match. Return $false;
        }

        if ($PSBoundParameters.ContainsKey('FullName') -and $FullName -ne $user.DisplayName)
        {
            Write-Verbose -Message ($LocalizedData.PropertyMismatch -f 'FullName', $FullName, $user.DisplayName)
            return $false; # The FullName property does not match. Return $false;
        }

        if ($PSBoundParameters.ContainsKey('Description') -and $Description -ne $user.Description)
        {
            Write-Verbose -Message ($LocalizedData.PropertyMismatch -f 'Description', $Description, $user.Description)
            return $false; # The Description property does not match. Return $false;
        }

        # Password
        if ($PSBoundParameters.ContainsKey('Password'))
        {
            if (-not $principalContext.ValidateCredentials($UserName, $Password.GetNetworkCredential().Password))
            {
                Write-Verbose -Message ($LocalizedData.PasswordPropertyMismatch -f 'Password')
                return $false; # The Password property does not match. Return $false;
            }
        }

        if ($PSBoundParameters.ContainsKey('Disabled') -and $Disabled -eq $user.Enabled)
        {
            Write-Verbose -Message ($LocalizedData.PropertyMismatch -f 'Disabled', $Disabled, $user.Enabled)
            return $false; # The Disabled property does not match. Return $false;
        }

        if ($PSBoundParameters.ContainsKey('PasswordNeverExpires') -and $PasswordNeverExpires -ne $user.PasswordNeverExpires)
        {
            Write-Verbose -Message ($LocalizedData.PropertyMismatch -f 'PasswordNeverExpires', $PasswordNeverExpires, $user.PasswordNeverExpires)
            return $false; # The PasswordNeverExpires property does not match. Return $false;
        }

        if ($PSBoundParameters.ContainsKey('PasswordChangeNotAllowed') -and $PasswordChangeNotAllowed -ne $user.UserCannotChangePassword)
        {
            Write-Verbose -Message ($LocalizedData.PropertyMismatch -f 'PasswordChangeNotAllowed', $PasswordChangeNotAllowed, $user.UserCannotChangePassword)
            return $false; # The PasswordChangeNotAllowed property does not match. Return $false;
        }
    }
    catch
    {
         New-ExceptionDueToDirectoryServicesError -ErrorId 'ConnectionError' -ErrorMessage ($LocalizedData.ConnectionError + $_)
    }

    finally
    {
        if ($null -ne $user)
        {
            $user.Dispose();
        }

        $principalContext.Dispose();

    }

    # All properties match. Return $true.
    Write-Verbose -Message ($LocalizedData.AllUserPropertisMatch -f 'User', $UserName)
    return $true;
}


<#
    .Synopsys
        The Get-TargetResource cmdlet.
#>
function Get-TargetResourceOnNanoServer
{
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName
    )

    Set-StrictMode -Version Latest

    Assert-UserNameValid -UserName $UserName

    # Try to find a user by a name.
    try
    {
        Write-Verbose -Message 'Starting Get-TargetResource on NanoServer'
        [Microsoft.PowerShell.Commands.LocalUser] $user = Get-LocalUser -Name $UserName -ErrorAction Stop
    }
    catch [System.Exception]
    {
        if ($_.CategoryInfo.ToString().Contains('UserNotFoundException'))
        {
            # The user is not found. Return Ensure=Absent.
            return @{
                        UserName = $UserName;
                        Ensure = 'Absent';
                    }
        }
        New-TerminatingError -ErrorRecord $_
    }

    # The user is found. Return all user properties and Ensure='Present'.
    $returnValue = @{
                        UserName = $user.Name;
                        Ensure = 'Present';
                        FullName = $user.FullName;
                        Description = $user.Description;
                        Disabled = -not $user.Enabled;
                        PasswordChangeRequired = $null;
                        PasswordChangeNotAllowed = -not $user.UserMayChangePassword;
                    }

    if ($user.PasswordExpires)
    {
        $returnValue.Add('PasswordNeverExpires', $false)
    }
    else
    {
        $returnValue.Add('PasswordNeverExpires', $true)
    }

    return $returnValue;
}

<#
    .SYNOPSIS
        The Set-TargetResource cmdlet on a Nano server.
#>
function Set-TargetResourceOnNanoServer
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName,

        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [System.String]
        $FullName,

        [System.String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Password,

        [System.Boolean]
        $Disabled,

        [System.Boolean]
        $PasswordNeverExpires,

        [System.Boolean]
        $PasswordChangeRequired,

        [System.Boolean]
        $PasswordChangeNotAllowed
    )

    Set-StrictMode -Version Latest

    Write-Verbose -Message ($LocalizedData.ConfigurationStarted -f $UserName)

    Assert-UserNameValid -UserName $UserName

    # Try to find a user by a name.
    $userExists = $false
    
    try
    {
        [Microsoft.PowerShell.Commands.LocalUser] $user = Get-LocalUser -Name $UserName -ErrorAction Stop
        $userExists = $true;
    }
    catch [System.Exception]
    {
        if ($_.CategoryInfo.ToString().Contains('UserNotFoundException'))
        {
            # The user is not found.
            Write-Verbose -Message ($LocalizedData.UserDoesNotExist -f $UserName)
        }
        else
        {
            New-TerminatingError -ErrorRecord $_
        }
    }

    if ($Ensure -eq 'Present')
    {
        # Ensure is set to 'Present'.

        if (-not $userExists)
        {
            # The user with the provided name does not exist. Add a new user.
            New-LocalUser -Name $UserName -NoPassword
            Write-Verbose -Message ($LocalizedData.UserCreated -f $UserName)
        }

        # Set user properties.
        if ($PSBoundParameters.ContainsKey('FullName'))
        {
            if (-not $userExists -or $FullName -ne $user.FullName)
            {
                if ($FullName -eq $null)
                {
                    Set-LocalUser -Name $UserName -FullName ([String]::Empty)
                }
                else
                {
                    Set-LocalUser -Name $UserName -FullName $FullName
                }
            }
        }
        else
        {
            if (-not $userExists)
            {
                # For a newly created user, set the DisplayName property to an empty string. By default DisplayName is set to user's name.
                Set-LocalUser -Name $UserName -FullName ([String]::Empty)
            }
        }

        if ($PSBoundParameters.ContainsKey('Description') -and (-not $userExists -or $Description -ne $user.Description))
        {
            if ($null -eq $Description)
            {
                Set-LocalUser -Name $UserName -Description ([String]::Empty)
            }
            else
            {
                Set-LocalUser -Name $UserName -Description $Description
            }
        }

        # Password. Set the password regardless of the state of the user.
        if ($PSBoundParameters.ContainsKey('Password'))
        {
            Set-LocalUser -Name $UserName -Password $Password.Password
        }

        if ($PSBoundParameters.ContainsKey('Disabled') -and ((-not $userExists) -or ($Disabled -eq $user.Enabled)))
        {
            if ($Disabled)
            {
                Disable-LocalUser -Name $UserName
            }
            else
            {
                Enable-LocalUser -Name $UserName
            }
        }

        $existingUserPasswordNeverExpires = (($userExists) -and ($null -eq $user.PasswordExpires))
        if ($PSBoundParameters.ContainsKey('PasswordNeverExpires') -and (-not $userExists -or ($PasswordNeverExpires -ne $existingUserPasswordNeverExpires)))
        {
            Set-LocalUser -Name $UserName -PasswordNeverExpires:$passwordNeverExpires
        }

        if ($PSBoundParameters.ContainsKey('PasswordChangeRequired') -and ($PasswordChangeRequired))
        {
            Set-LocalUser -Name $UserName -AccountExpires ([datetime]::Now)
        }

        # NOTE: The parameter name and the property name have opposite meaning.
        [System.Boolean] $expected = -not $PasswordChangeNotAllowed
        $actual = $expected
        
        if ($userExists)
        {
            $actual = $user.UserMayChangePassword
        }
        
        if ($PSBoundParameters.ContainsKey('PasswordChangeNotAllowed') -and (-not $userExists -or $expected -ne $actual))
        {
            Set-LocalUser -Name $UserName -UserMayChangePassword $expected
        }
    }
    else
    {
        # Ensure is set to 'Absent'.
        if ($userExists)
        {
            # The user exists.
            Remove-LocalUser -Name $UserName

            Write-Verbose -Message ($LocalizedData.UserRemoved -f $UserName)
        }
        else
        {
            Write-Verbose -Message ($LocalizedData.NoConfigurationRequiredUserDoesNotExist -f $UserName)
        }
    }

    Write-Verbose -Message ($LocalizedData.ConfigurationCompleted -f $UserName)
}

<#
    .SYNOPSIS
        The Test-TargetResource cmdlet on a Nano server.
    .NOTES
        There's no easy way to check whether the PasswordChangeRequired is set
        to true or false, so this value is not tested here
#>
function Test-TargetResourceOnNanoServer
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName,

        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [System.String]
        $FullName,

        [System.String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Password,

        [System.Boolean]
        $Disabled,

        [System.Boolean]
        $PasswordNeverExpires,

        [System.Boolean]
        $PasswordChangeRequired,

        [System.Boolean]
        $PasswordChangeNotAllowed
    )

    Set-StrictMode -Version Latest

    Assert-UserNameValid -UserName $UserName

    # Try to find a user by a name.
    try
    {
        [Microsoft.PowerShell.Commands.LocalUser] $user = Get-LocalUser -Name $UserName -ErrorAction Stop
    }
    catch [System.Exception]
    {
        if ($_.CategoryInfo.ToString().Contains('UserNotFoundException'))
        {
            # The user is not found. Return Ensure=Absent.
            if ($Ensure -eq 'Absent')
            {
                return $true
            }
            else
            {
                return $false
            }
        }
        New-TerminatingError -ErrorRecord $_
    }

    # A user with the provided name exists.
    Write-Verbose -Message ($LocalizedData.UserExists -f $UserName)

    # Validate separate properties.
    if ($Ensure -eq 'Absent')
    {
        Write-Verbose -Message ($LocalizedData.PropertyMismatch -f 'Ensure', 'Absent', 'Present')
        return $false; # The Ensure property does not match. Return $false;
    }

    if ($PSBoundParameters.ContainsKey('FullName') -and $FullName -ne $user.FullName)
    {
        Write-Verbose -Message ($LocalizedData.PropertyMismatch -f 'FullName', $FullName, $user.FullName)
        return $false; # The FullName property does not match. Return $false;
    }

    if ($PSBoundParameters.ContainsKey('Description') -and $Description -ne $user.Description)
    {
        Write-Verbose -Message ($LocalizedData.PropertyMismatch -f 'Description', $Description, $user.Description)
        return $false; # The Description property does not match. Return $false;
    }

    if ($PSBoundParameters.ContainsKey('Password'))
    {
        if(-not (Test-ValidCredentialsOnNanoServer -UserName $UserName -Password $Password.Password))
        {
            Write-Verbose -Message ($LocalizedData.PasswordPropertyMismatch -f 'Password')
            return $false; # The Password property does not match. Return $false;
        }
    }

    if ($PSBoundParameters.ContainsKey('Disabled') -and ($Disabled -eq $user.Enabled))
    {
        Write-Verbose -Message ($LocalizedData.PropertyMismatch -f 'Disabled', $Disabled, $user.Enabled)
        return $false; # The Disabled property does not match. Return $false;
    }

    $existingUserPasswordNeverExpires = ($null -eq $user.PasswordExpires)
    if ($PSBoundParameters.ContainsKey('PasswordNeverExpires') -and $PasswordNeverExpires -ne $existingUserPasswordNeverExpires)
    {
        Write-Verbose -Message ($LocalizedData.PropertyMismatch -f 'PasswordNeverExpires', $PasswordNeverExpires, $existingUserPasswordNeverExpires)
        return $false; # The PasswordNeverExpires property does not match. Return $false;
    }

    if ($PSBoundParameters.ContainsKey('PasswordChangeNotAllowed') -and $PasswordChangeNotAllowed -ne (-not $user.UserMayChangePassword))
    {
        Write-Verbose -Message ($LocalizedData.PropertyMismatch -f 'PasswordChangeNotAllowed', $PasswordChangeNotAllowed, (-not $user.UserMayChangePassword))
        return $false; # The PasswordChangeNotAllowed property does not match. Return $false;
    }

    # All properties match. Return $true.
    Write-Verbose -Message ($LocalizedData.AllUserPropertisMatch -f 'User', $UserName)
    return $true;
}

<#
    .SYNOPSIS
        Checks that the User name does not contain invalid characters.
#>
function Assert-UserNameValid
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName
    )

    # Check if the name consists of only periods and/or white spaces.
    $wrongName = $true;
    
    for ($i = 0; $i -lt $UserName.Length; $i++)
    {
        if (-not [Char]::IsWhiteSpace($UserName, $i) -and $UserName[$i] -ne '.')
        {
            $wrongName = $false;
            break;
        }
    }

    $invalidChars = @('\','/','"','[',']',':','|','<','>','+','=',';',',','?','*','@')

    if ($wrongName)
    {
        New-InvalidArgumentError -ErrorId 'UserNameHasOnlyWhiteSpacesAndDots' -ErrorMessage ($LocalizedData.InvalidUserName -f $UserName, [string]::Join(' ', $invalidChars))
    }

    if ($UserName.IndexOfAny($invalidChars) -ne -1)
    {
        New-InvalidArgumentError -ErrorId 'UserNameHasInvalidCharachter' -ErrorMessage ($LocalizedData.InvalidUserName -f $UserName, [string]::Join(' ', $invalidChars))
    }
}

<#
    .SYNOPSIS
        Throws an argument error.
#>
function New-InvalidArgumentError
{
    [CmdletBinding()]
    param
    (

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ErrorId,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ErrorMessage
    )

    $errorCategory=[System.Management.Automation.ErrorCategory]::InvalidArgument
    $exception = New-Object System.ArgumentException $ErrorMessage;
    $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $ErrorId, $errorCategory, $null
    throw $errorRecord
}

<#
        Creates a new Connection error record and throws it
#>
function New-ExceptionDueToDirectoryServicesError
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ErrorId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ErrorMessage
    )

    $errorCategory = [System.Management.Automation.ErrorCategory]::ConnectionError
    $exception = New-Object System.ArgumentException $ErrorMessage
    $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $ErrorId, $errorCategory, $null
    throw $errorRecord
}

<#
    .SYNOPSIS
        Create a new terminating error record and throws it
#>
function New-TerminatingError
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $Message,
        
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )


    if ($null -ne $ErrorRecord)
    {
        $exception = New-Object 'System.InvalidOperationException' $Message, $ErrorRecord.Exception
    }
    else
    {
        $exception = New-Object 'System.InvalidOperationException' $Message
    }
    
    $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, 'MachineStateIncorrect', 'InvalidOperation', $null
    throw $errorRecord
}

<#
    .SYNOPSIS
        Tests the local user's credentials on the local machine.
#>
function Test-ValidCredentialsOnNanoServer
{
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName,

        [ValidateNotNullOrEmpty()]
        [SecureString]
        $Password
    )

    $source = @'
        [Flags]
        private enum LogonType
        {
            Logon32LogonInteractive = 2,
            Logon32LogonNetwork,
            Logon32LogonBatch,
            Logon32LogonService,
            Logon32LogonUnlock,
            Logon32LogonNetworkCleartext,
            Logon32LogonNewCredentials
        }

        [Flags]
        private enum LogonProvider
        {
            Logon32ProviderDefault = 0,
            Logon32ProviderWinnt35,
            Logon32ProviderWinnt40,
            Logon32ProviderWinnt50
        }

        [DllImport("api-ms-win-security-logon-l1-1-1.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern Boolean LogonUser(
            String lpszUserName,
            String lpszDomain,
            IntPtr lpszPassword,
            LogonType dwLogonType,
            LogonProvider dwLogonProvider,
            out IntPtr phToken
            );


        [DllImport("api-ms-win-core-handle-l1-1-0.dll",
            EntryPoint = "CloseHandle", SetLastError = true,
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool CloseHandle(IntPtr handle);

        public static bool ValidateCredentials(string username, SecureString password)
        {
            IntPtr tokenHandle = IntPtr.Zero;
            IntPtr unmanagedPassword = IntPtr.Zero;

            unmanagedPassword = SecureStringMarshal.SecureStringToCoTaskMemUnicode(password);

            try
            {
                return LogonUser(
                    username,
                    null,
                    unmanagedPassword,
                    LogonType.Logon32LogonInteractive,
                    LogonProvider.Logon32ProviderDefault,
                    out tokenHandle);
            }
            catch
            {
                return false;
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    CloseHandle(tokenHandle);
                }
                if (unmanagedPassword != IntPtr.Zero) {
                    Marshal.ZeroFreeCoTaskMemUnicode(unmanagedPassword);
                }
                unmanagedPassword = IntPtr.Zero;
            }
        }
'@

    Add-Type -PassThru -Namespace Microsoft.Windows.DesiredStateConfiguration.NanoServer.UserResource `
        -Name CredentialsValidationTool -MemberDefinition $source -Using System.Security -ReferencedAssemblies System.Security.SecureString.dll | Out-Null
    return [Microsoft.Windows.DesiredStateConfiguration.NanoServer.UserResource.CredentialsValidationTool]::ValidateCredentials($UserName, $Password)
}

Export-ModuleMember -Function *-TargetResource
