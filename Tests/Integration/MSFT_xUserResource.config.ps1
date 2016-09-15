
# Integration Test Config Template Version 1.0.0

        

Configuration MSFT_xUser_NewUser
{
    param 
    (
        [String]
        $UserName = 'Test UserName',
        
        [String]
        $Description = 'Test Description',
        
        [String]
        $FullName = 'Test Full Name',
        
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',
        
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]
        $Password
    )
    
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'
    
    Node Localhost {

        xUser UserResource1
        {
            UserName = $UserName
            Ensure = $Ensure
            FullName = $FullName
            Description = $Description
            Password = $Password
        }
    }
}
