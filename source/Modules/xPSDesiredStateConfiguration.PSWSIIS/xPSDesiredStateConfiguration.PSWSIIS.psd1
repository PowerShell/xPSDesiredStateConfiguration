@{
    # Version number of this module.
    ModuleVersion     = '1.0.0.0'

    # ID used to uniquely identify this module
    GUID              = '63b5d3ab-7f33-4647-970b-cbab5532116f'

    # Author of this module
    Author            = 'DSC Community'

    # Company or vendor of this module
    CompanyName       = 'DSC Community'

    # Copyright statement for this module
    Copyright         = 'Copyright the DSC Community contributors. All rights reserved.'

    # Description of the functionality provided by this module
    Description       = 'This module contains a utility to perform PSWS IIS Endpoint setup.'

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        'New-ResourceSetConfigurationScriptBlock',
        'New-PSWSEndpoint',
        'Set-AppSettingsInWebconfig',
        'Set-BindingRedirectSettingInWebConfig',
        'Remove-PSWSEndpoint'
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = @(
        'DscWebServiceDefaultAppPoolName'
    )

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport   = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{

        PSData = @{
        } # End of PSData hashtable

    } # End of PrivateData hashtable
}
