!include "logiclib.nsh"

# define name of installer
OutFile "bin\gotls-installer.exe"

# define install dir (no 32-bit support)
InstallDir "$LocalAppData\Programs\goTLS"

RequestExecutionLevel user

Section
    SetOutPath $INSTDIR

    File bin\gotls.exe

    # create uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"

    # create application shortcut in start menu
    CreateShortcut "$SMPROGRAMS\goTLS.lnk" "C:\Windows\system32\cmd.exe" "/k echo try gotls -h"

    # check for environment variable write access
    EnVar::SetHKCU
    EnVar::Check "NULL" "NULL"
    Pop $0
    ${If} $0 <> 0
      DetailPrint "EnVar::Check write access error in HKCU, returned:$0"
    ${EndIf}

    # add INSTDIR to HKCU path
    EnVar::Check "Path" "$INSTDIR"
    Pop $0
    ${If} $0 <> 0
      EnVar::AddValue "Path" "$INSTDIR"
      Pop $0
      ${If} $0 <> 0
        DetailPrint "EnVar::AddValue error, %path% unchanged, returned:$0"
      ${EndIf}
    ${EndIf}
SectionEnd

Section "uninstall"
    # remove binary
    Delete "$INSTDIR\gotls.exe"

    # remove link from start menu
    Delete "$SMPROGRAMS\goTLS.lnk"

    # delete uninstaller
    Delete "$INSTDIR\uninstall.exe"

    # delete the install dir
    RMDir $INSTDIR

    # check for environment variable write access
    EnVar::SetHKCU
    EnVar::Check "NULL" "NULL"
    Pop $0
    ${If} $0 <> 0
      DetailPrint "EnVar::Check write access error in HKCU, returned:$0"
    ${EndIf}

    # remove INSTDIR from HKCU path
    EnVar::DeleteValue "Path" "$INSTDIR"
    Pop $0
    ${If} $0 <> 0
      DetailPrint "EnVar::DeleteValue error, %path% unchanged, returned:$0"
    ${EndIf}
SectionEnd
