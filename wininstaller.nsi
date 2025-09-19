# define name of installer
OutFile "gotls-installer.exe"

# define installation directory
InstallDir $DESKTOP

# For removing Start Menu shortcut in Windows 7
RequestExecutionLevel user

Section
    # set the installation directory as the destination for the following actions
    SetOutPath $INSTDIR

    File gotls.exe

    # create the uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"

    # create a shortcut named "goTLS" in the start menu programs directory
    # point the new shortcut at the program uninstaller
    CreateShortcut "$SMPROGRAMS\goTLS.lnk" "C:\Windows\system32\cmd.exe" "/k 'echo try gotls -h'"

    ; Add your application's installation directory to the system PATH
    ; Replace "YourAppPath" with the actual path, e.g., "$INSTDIR\Bin"
 #   EnvVarUpdate $0 "PATH" "A" "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "$INSTDIR"
#TODO: Use https://nsis.sourceforge.io/EnVar_plug-in instead

    ; Alternatively, for user-specific PATH:
    ; EnvVarUpdate $0 "PATH" "A" "HKCU\Environment" "YourAppPath"
SectionEnd

Section "uninstall"

    # Remove the link from the start menu
    Delete "$SMPROGRAMS\goTLS.lnk"

    # Delete the uninstaller
    Delete $INSTDIR\uninstaller.exe

    RMDir $INSTDIR

#    EnvVarUpdate $0 "PATH" "R" "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "$INSTDIR"
SectionEnd
