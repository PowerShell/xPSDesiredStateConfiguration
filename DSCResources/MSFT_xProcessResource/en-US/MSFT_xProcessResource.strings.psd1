# Localized resources for MSFT_xProcessResource

ConvertFrom-StringData @'
    AbsolutePathOrFileName = Absolute path or file name expected.
    CouldNotCreateProcessError = Could not create process. Error code: 
    DuplicateTokenError = Duplicate token. Error code: 
    FileNotFound = File not found in the environment path.
    ErrorCredentialParameterNotSupportedWithRunAsCredential = The PsDscRunAsCredential parameter is not supported by the Process resource, and cannot be used with the Credential parameter. To start the process with user '{0}', use only the Credential parameter, not the PsDscRunAsCredential parameter.
    ErrorInvalidUserName = Invalid username: {0}. Username cannot contain multiple '@' or multiple '\'
    ErrorParametersNotSupportedWithCredential = Can't specify StandardOutputPath, StandardInputPath or WorkingDirectory when trying to run a process under a user context.
    ErrorRunAsCredentialParameterNotSupported = The PsDscRunAsCredential parameter is not supported by the Process resource. To start the process with user '{0}', add the Credential parameter.
    ErrorStarting = Failure starting process matching path '{0}'. Message: {1}.
    ErrorStopping = Failure stopping processes matching path '{0}' with IDs '({1})'. Message: {2}.
    FailureWaitingForProcessesToStart = Failed to wait for processes to start.
    FailureWaitingForProcessesToStop = Failed to wait for processes to stop.
    GetTargetResourceStartMessage = Begin executing Get functionality for the process {0}.
    GetTargetResourceEndMessage = End executing Get functionality for the process {0}.
    InvalidArgument = Invalid argument: '{0}' with value: '{1}'.
    InvalidArgumentAndMessage = {0} {1}
    OpenProcessTokenError = Error while opening process token. Error code: 
    ParameterShouldNotBeSpecified = Parameter {0} should not be specified.
    PathShouldBeAbsolute = The path should be absolute.
    PathShouldExist = The path should exist.
    PrivilegeLookingUpError = Error while looking up privilege. Error code: 
    ProcessAlreadyStarted = Process matching path '{0}' found running. No action required.
    ProcessAlreadyStopped = Process matching path '{0}' not found running. No action required.
    ProcessesStarted = Processes matching path '{0}' started.
    ProcessesStopped = Processes matching path '{0}' with IDs '({1})' stopped.
    RetriveStatusError = Failed to retrieve status. Error code: 
    SetTargetResourceStartMessage = Begin executing Set functionality for the process {0}.
    SetTargetResourceEndMessage = End executing Set functionality for the process {0}.
    StartingProcessWhatif = Start-Process.
    StoppingProcessWhatIf = Stop-Process.
    TestTargetResourceStartMessage = Begin executing Test functionality for the process {0}.
    TestTargetResourceEndMessage = End executing Test functionality for the process {0}.
    TokenElevationError = Error while getting token elevation. Error code: 
    UserCouldNotBeLoggedError = User could not be logged. Error code: 
    WaitFailedError = Failed while waiting for process. Error code: 
    VerboseInProcessHandle = In process handle {0}.
'@
