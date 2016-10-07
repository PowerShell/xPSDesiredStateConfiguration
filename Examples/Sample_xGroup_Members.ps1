<#
    .SYNOPSIS
        Creates a group with the specified name and members or modifies the members of a group if
        the named group already exists.

    .PARAMETER GroupName
        The name of the group to create or modify.

    .PARAMETER Members
        The list of members the group should have.
        The default value is an empty list which will remove all members from the group.
#>
Configuration Sample_xGroup
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [String[]]
        $Members = @()
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    xGroup Group1
    {
        GroupName = $GroupName
        Ensure = 'Present'
        Members = $Members
    }
}