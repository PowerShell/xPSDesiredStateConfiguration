<#
    .SYNOPSIS
        Creates a set of groups with the specified names and members included/excluded
        or modifies the members of the set of groups  with the specified names if they already
        exist.

    .PARAMETER GroupName
        The names of the groups to create or modify.

    .PARAMETER MembersToInclude
        The list of members all groups in the set should include.
        The default value is an empty list.

    .PARAMETER MembersToExclude
        The list of members all groups in the set should exclude.
        The default value is an empty list.
#>
Configuration Sample_xGroupSet
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $GroupName,

        [String[]]
        $MembersToInclude = @(),

        [String[]]
        $MembersToExclude = @()
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    xGroupSet GroupSet1
    {
        GroupName = $GroupName
        Ensure = 'Present'
        MembersToInclude = $MembersToInclude
        MembersToExclude = $MembersToExclude
    }
}
