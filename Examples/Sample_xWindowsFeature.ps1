Configuration xWindowsFeatureExample
{
    Import-DSCResource -ModuleName xPSDesiredStateConfiguration

    xWindowsFeature RoleExample
    {
        # Alternatively, to ensure the role is uninstalled, set Ensure to 'Absent'
        Ensure = 'Present'
        # Use the Name property from Get-WindowsFeature
        Name = 'Web-Server'
    }
}
