﻿<#
    .SYNOPSIS
        Modifies the 'Path' environment variable, appending the value
        'C:\TestValue' if it doesn't already exist. Ensure that Path is
        set to $true in order to append/remove values and not completely
        replace the Path environment variable.
#>
Configuration Sample_xEnvironment_CreatePathVariable 
{
    param ()

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xEnvironment CreatePathEnvironmentVariable
        {
            Name = 'Path'
            Value = 'C:\TestValue'
            Ensure = 'Present'
            Path = $true
            Target = @('Process', 'Machine')
        }
    }
}

Sample_xEnvironment_CreatePathVariable
