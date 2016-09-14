# PSDesiredStateConfiguration High Quality Resource Module Plan
Any comments or questions about this plan can be submitted under issue [#160](https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/160)

## Goals 
  1. Port the appropriate in-box DSC Resources to the open-source xPSDesiredStateConfiguration resource module. 
  2. Make the open-source xPSDesiredStateConfiuration resource module a **High Quality Resource Module (HQRM)** to present to the community for feedback.

The PSDesiredStateConfiguration High Quality Resource Module will consist of the following resources:
- Archive
- DSCWebService
- Environment
- Group
- GroupSet
- Package
- Process
- ProcessSet
- PSSessionConfiguration
- Registry
- Script
- Service
- ServiceSet
- User
- WindowsFeature
- WindowsFeatureSet
- WindowsOptionalFeature
- WindowsOptionalFeatureSet
- WindowsPackageCab (**NEW**)

## Progress

- [ ] [1. Port In-Box Only Resources](#port-in-box-only-resources)
  - [x] Environment
  - [x] GroupSet
  - [x] ProcessSet
  - [x] Script
  - [x] ServiceSet
  - [x] User
  - [x] WindowsFeature
  - [x] WindowsFeatureSet
  - [x] WindowsOptionalFeatureSet
  - [ ] WindowsPackageCap (**NEW**) (In Progress)
- [x] [2. Merge In-Box & Open-Source Resources](#merge-in-box-and-open-source-resources) 
  - [x] Archive
  - [x] Group
  - [x] Package
  - [X] Process 
  - [x] Registry 
  - [x] Service
  - [x] WindowsOptionalFeature
- [x] [3. Resolve Nano Server vs. Full Server Resources](#resolve-nano-server-vs-full-server-resources)
    The general consensus is to leave the if-statements for now.
- [ ] [4. Update the Resource Module to a High Quality Resource Module](#update-the-resource-module-to-a-high-quality-resource-module)
  - 1. Fix PSSA issues per the [DSC Resource Kit PSSA Rule Severity List](https://github.com/PowerShell/DscResources/blob/master/PSSARuleSeverities.md).  
  - 2. Ensure unit tests are present for each resource with more than 70% code coverage. (In Progress) 
  - 3. Ensure examples run correctly, work as expected, and are documented clearly.  
  - 4. Ensure clear documentation is provided.  
  - 5. Ensure the PSDesiredStateConfiguration module follows the standard DSC Resource Kit module format.  
  - 6. Fix code styling to match the [DSC Resource Kit Style Guidelines](https://github.com/PowerShell/DscResources/blob/master/StyleGuidelines.md).
  - [ ] Archive
  - [ ] DSCWebService
  - [ ] Environment
  - [ ] Group
  - [ ] GroupSet
  - [ ] Package
  - [ ] Process
  - [ ] ProcessSet
  - [ ] PSSessionConfiguration
  - [ ] Registry
  - [ ] Script
  - [ ] Service
  - [ ] ServiceSet
  - [ ] User
  - [ ] WindowsFeature
  - [ ] WindowsFeatureSet
  - [x] WindowsOptionalFeature
  - [ ] WindowsOptionalFeatureSet
  - [ ] WindowsPackageCab (**NEW**) (In Progress)
- [ ] [5. Resolve Name of New High Quality Resource Module](#resolve-name-of-new-high-quality-resource-module)
  - [ ] 1. Move the entire module to a new GitHub repository with the correct name.  
  - [ ] 2. Rename the module files.  
  - [ ] 3. Rename all DSC resources.  
  - [ ] 4. Update the names of the resources in all dependent files.

## Port In-Box Only Resources
We will port the appropriate in-box resources that will be in the HQRM to the open-source xPSDesiredStateConfiguration resource module. These resources are not currently in the open-source repository. Resources currently both in-box and open-source will be merged in step 2.

### In-Box Only Resources Moving to Open-Source HQRM
These resources and any of their tests, examples, or documentation will be moved to the xPSDSC open-source repository:
- Environment
- GroupSet
- ProcessSet
- Script
- ServiceSet
- User
- WindowsFeature
- WindowsFeatureSet
- WindowsOptionalFeatureSet
- WindowsPackageCab (**NEW**)

When these resources are moved to GitHub, they will have 'x' appended before their names for now to indicate that they are still 'experimental' in this stage. This 'x' convention will change in the near future. The 'x' can be removed as part of step 5.

## Merge In-Box and Open-Source Resources
We will merge in-box resources that are also currently in the open-source module. The in-box resources and any of their tests, examples, or documentation will be merged into the existing open-source resources in the xPSDesiredStateConfiguration resource module.

Four of the current open-source resources are not provided in-box. The fate of these open-source-only resources has been addressed in this step as well. 

### Open-Source Resources Moving to HQRM
\* = open-source only

- Archive
- DSCWebService*
- Group
- PSSessionConfiguration*
- Package
- Process
- Registry
- Service
- WindowsOptionalFeature

These resources will retain the 'x' appended before their names for now to indicate that they are still 'experimental' in this stage. This 'x' convention will change in the near future. The 'x' can be removed as part of step 5.

### Open-Source Resources Not Moving to HQRM
| Resource Name | Reason Not to Move |
|---------------|--------------------|
| FileUpload | This should be part of the File resource. We do not want this released as an official, supported resource when we are planning to change it in the future. |
| RemoteFile | This should be part of the File resource. We do not want this released as an official, supported resource when we are planning to change it in the future. |

## Resolve Nano Server vs Full Server Resources
Some of the in-box resources (User especially) currently contain all-encompassing if-statements which tells the resource to act differently based on whether it is operating on a Nano server or a full server. These if-statements will make the resources difficult to maintain.

### Potential Solutions
| Solution | Pros | Cons |
|----------|------|------|
| Leave the if-statements | <ul><li> No time needed for fix. </li></ul> | <ul><li> Difficult to maintain. </li><li> User has to download/store extra code. (minimal) </li></ul> |
| Use the Nano server version only | <ul><li> Code will be easy to maintain. </li><li> May be a cleaner, simpler implementation for full server. </li><li> User does not have to download/store extra code. (minimal) </li></ul> | <ul><li> May break the resources. </li><li> Requires fixing time. </li><li> Requires testing. </li></ul> |
| Separate the Nano and full server versions into separate resources | <ul><li> User can download only the resource version they need. </li></ul> | <ul><li> Will have to maintain separate version. </li><li> Requires fixing time. </li><li> Requires testing. </li></ul> | 

## Update the Resource Module to a High Quality Resource Module
We will update the resouces, tests, exmaples, and documentation to ensure that the xPSDesiredStateConfiguration resource module meets the requirements to be a High Quality Resource Module (HQRM). These requirements can be found in the DSC Resource Kit High Quality Plan (not yet published publicly, sorry).  

Here are the basic steps we will have to take based on this plan:  
1. Fix PSSA issues per the DSC Resource Kit PSSA Rule Severity List (not yet published publicly, sorry).  
2. Ensure unit tests are present for each resource with more than 70% code coverage.  
3. Ensure examples run correctly, work as expected, and are documented clearly.  
4. Ensure clear documentation is provided.  
5. Ensure the PSDesiredStateConfiguration module follows the standard DSC Resource Kit module format.  
6. Fix code styling to match the [DSC Resource Kit Style Guidelines](https://github.com/PowerShell/DscResources/blob/master/StyleGuidelines.md).  

## Resolve Name of New High Quality Resource Module
The new High Quality module for xPSDesiredStateConfiguration will be named PSDsc.

It cannot be named PSDesiredStateCongfiguration since that would conflict with the in-box module, but this HQRM will not contain all the resources in the in-box module (File cannot be ported).
'PSDsc' also follows to convention of other HQRM's which end in 'Dsc'.

All resources will have the 'x' removed in the HQRM.

Renaming the module and its resources will require a few different steps:  
1. Move the entire module to a new GitHub repository with the correct name.  
2. Rename the module files.  
3. Rename all DSC resources.  
4. Update the names of the resources in all dependent files.
