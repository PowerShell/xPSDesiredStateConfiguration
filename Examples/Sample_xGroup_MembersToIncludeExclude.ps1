<#
    .SYNOPSIS
        Creates a group with the specified name and members included or modifies the members of a group if
        the named group already exists.

    .PARAMETER GroupName
        The name of the group to create or modify.

    .PARAMETER MembersToInclude
        The list of members the group should contain.
        The default value is an empty list.

    .PARAMETER MembersToExclude
        The list of members the group should not contain.
        The default value is an empty list.
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
        $MembersToInclude = @(),

        [String[]]
        $MembersToExclude = @()
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    xGroup Group1
    {
        GroupName = $GroupName
        Ensure = 'Present'
        MembersToInclude = $MembersToInclude
        MembersToExclude = $MembersToExclude
    }
}