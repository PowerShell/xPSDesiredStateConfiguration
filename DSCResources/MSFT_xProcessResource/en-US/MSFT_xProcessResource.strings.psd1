# Localized resources for MSFT_xProcessResource

ConvertFrom-StringData @'
    FileNotFound = File not found in the environment path.
    AbsolutePathOrFileName = Absolute path or file name expected.
    InvalidArgument = Invalid argument: '{0}' with value: '{1}'.
    InvalidArgumentAndMessage = {0} {1}
    ProcessStarted = Process matching path '{0}' started.
    ProcessesStopped = Processes matching path '{0}' with IDs '({1})' stopped.
    ProcessAlreadyStarted = Process matching path '{0}' found running. No action required.
    ProcessAlreadyStopped = Process matching path '{0}' not found running. No action required.
    ErrorStopping = Failure stopping processes matching path '{0}' with IDs '({1})'. Message: {2}.
    ErrorStarting = Failure starting process matching path '{0}'. Message: {1}.
    StartingProcessWhatif = Start-Process.
    StoppingProcessWhatIf = Stop-Process.
    ProcessNotFound = Process matching path '{0}' not found.
    PathShouldBeAbsolute = The path should be absolute.
    PathShouldExist = The path should exist.
    ParameterShouldNotBeSpecified = Parameter {0} should not be specified.
    FailureWaitingForProcessesToStart = Failed to wait for processes to start.
    FailureWaitingForProcessesToStop = Failed to wait for processes to stop.
    ErrorParametersNotSupportedWithCredential = Can't specify StandardOutputPath, StandardInputPath or WorkingDirectory when trying to run a process under a user context.
    VerboseInProcessHandle = In process handle {0}.
    ErrorRunAsCredentialParameterNotSupported = The PsDscRunAsCredential parameter is not supported by the Process resource. To start the process with user '{0}', add the Credential parameter.
    ErrorCredentialParameterNotSupportedWithRunAsCredential = The PsDscRunAsCredential parameter is not supported by the Process resource, and cannot be used with the Credential parameter. To start the process with user '{0}', use only the Credential parameter, not the PsDscRunAsCredential parameter.
    GetTargetResourceStartMessage = Begin executing Get functionality for the process {0}.
    GetTargetResourceEndMessage = End executing Get functionality for the process {0}.
    SetTargetResourceStartMessage = Begin executing Set functionality for the process {0}.
    SetTargetResourceEndMessage = End executing Set functionality for the process {0}.
    TestTargetResourceStartMessage = Begin executing Test functionality for the process {0}.
    TestTargetResourceEndMessage = End executing Test functionality for the process {0}.
'@
