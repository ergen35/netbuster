; Installateur Windows de NetBuster (Inno Setup). Lancé par packaging/windows/build.ps1.
; Il s'installe pour le compte seul : aucun droit administrateur n'est demandé.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6F2B7C1E-3D54-4B8A-9E21-7A0C5D3E8F14}
AppName=NetBuster
AppVersion={#AppVersion}
AppPublisher=Serge Eric Hotegni
AppPublisherURL=https://github.com/ergen35/netbuster
DefaultDirName={autopf}\NetBuster
DefaultGroupName=NetBuster
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist
OutputBaseFilename=netbuster-{#AppVersion}-windows-x64-setup
SetupIconFile=..\..\assets\windows\netbuster.ico
UninstallDisplayIcon={app}\netbuster.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\..\target\release\netbuster.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\NetBuster"; Filename: "{app}\netbuster.exe"
Name: "{autodesktop}\NetBuster"; Filename: "{app}\netbuster.exe"; Tasks: desktopicon

[Registry]
; Le réglage « ouvrir à l'ouverture de session » disparaît avec le programme.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "NetBuster"; Flags: dontcreatekey uninsdeletevalue

[Run]
Filename: "{app}\netbuster.exe"; Description: "{cm:LaunchProgram,NetBuster}"; Flags: nowait postinstall skipifsilent
