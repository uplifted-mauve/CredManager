# CredManager
A simple command line utility to batch remove credentials from the [Windows Credential Manager](https://support.microsoft.com/en-us/windows/accessing-credential-manager-1b5c916a-6a16-889f-8581-fc16e8165ac0)

It appears that the Windows Credential Manager has a size limit, and some applications can be sloppy, storing large credential blobs and never cleaning them up. Once the Credential Manager hits its limit, no new credential can be added, potentially causing issues to software relying on it. 

## Usage
```text
CredManager.exe [filter] [age]
  filter - string including wildcard to select which credentials to query (max 255 char). Defaults to Adobe*
  age - delete credentials older than x number of days
```

Example, for removing all Xbox credentials older than ~6 months:

`CredManager.exe Xbl* 180`