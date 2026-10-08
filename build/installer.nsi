; ============================================================
;  Sentinel 安装脚本  (NSIS 3.x)
;  编译：makensis.exe -XSetCompressor /SOLID lzma installer.nsi
; ============================================================
Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

!define APP        "Sentinel-Ccufo"
!define PUBLISH    "..\publish"
!define DIST       "..\dist"
!define VERSION    "1.0.0"

Name "${APP} ${VERSION} 安装程序"
OutFile "${DIST}\Sentinel-Ccufo-Setup-${VERSION}.exe"
InstallDir "$PROGRAMFILES64\${APP}"
InstallDirRegKey HKLM "Software\${APP}" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName"     "${APP}"
VIAddVersionKey "ProductVersion"  "${VERSION}"
VIAddVersionKey "FileDescription" "SMB 端口暴露实时监控与一键处置工具"
VIAddVersionKey "CompanyName"     "Sentinel"
VIAddVersionKey "LegalCopyright"  "Copyright (C) 2026"
VIAddVersionKey "FileVersion"     ".0"

!define MUI_ABORTWARNING
!define MUI_ICON   "..\assets\sentinel.ico"
!define MUI_UNICON "..\assets\sentinel.ico"
!define MUI_FINISHPAGE_RUN "$INSTDIR\Sentinel-Ccufo.exe"
!define MUI_FINISHPAGE_RUN_TEXT "启动 ${APP}"
!define MUI_FINISHPAGE_RUN_CHECKED
!define MUI_FINISHPAGE_SHOWINSTFILES
!define MUI_UNCONFIRMPAGE_TEXT_TOP "卸载  。\r\n\r\n程序目录：\r\n\r\n注意：卸载时会自动移除本程序创建的所有防火墙规则，并把「文件和打印机共享」规则组恢复为启用状态。"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "SimpChinese"
!insertmacro MUI_LANGUAGE "English"

Var KeepSettings
Var Launched

; ---------------------------------------------------------------- 初始化
Function .onInit
  StrCpy $KeepSettings "0"
  StrCpy $Launched "0"
FunctionEnd

Function un.onInit
  StrCpy $KeepSettings "0"
  StrCpy $Launched "0"
FunctionEnd

; ---------------------------------------------------------------- 安装
Section "安装核心文件" SecMain
  ; 清理可能残留的旧目录
  IfFileExists "$INSTDIR\*" 0 +2
    RMDir /r "$INSTDIR"

  SetOutPath "$INSTDIR"
  File "${PUBLISH}\Sentinel-Ccufo.exe"

  ; 写入注册表
  WriteRegStr HKLM "Software\${APP}" "InstallDir"  "$INSTDIR"
  WriteRegStr HKLM "Software\${APP}" "Version"    "${VERSION}"
  WriteRegStr HKLM "Software\${APP}" "Installed"  "1"

  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"  "DisplayName"     "${APP}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"  "DisplayVersion"  "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"  "Publisher"       "Sentinel"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"  "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"  "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"  "HelpLink"        "https://github.com/"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"  "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"  "NoRepair" 1

  ; 开始菜单 + 桌面快捷方式
  CreateDirectory "$SMPROGRAMS\${APP}"
  CreateDirectory "$SMPROGRAMS\${APP}\卸载"
  CreateShortcut "$SMPROGRAMS\${APP}\${APP}.lnk"      "$INSTDIR\Sentinel-Ccufo.exe"
  CreateShortcut "$SMPROGRAMS\${APP}\卸载\卸载.lnk""$INSTDIR\Uninstall.exe"
  CreateShortcut "$DESKTOP\${APP}.lnk"                "$INSTDIR\Sentinel-Ccufo.exe"

  ; 卸载器
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; 首次运行时自动启用「登录即启动到托盘」
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run"  "${APP}" '"$INSTDIR\Sentinel-Ccufo.exe" --tray'
SectionEnd

; ---------------------------------------------------------------- 可选任务
Section "开机自动启动（托盘常驻）" SecStartup
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run"  "${APP}" '"$INSTDIR\Sentinel-Ccufo.exe" --tray'
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain}  "复制主程序、创建快捷方式与卸载入口。这是必需组件。"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStartup}  "登录 Windows 后自动以托盘形式启动，持续在后台监控 SMB 暴露。\r\n\r\n建议勾选：监控工具的价值在于持续运行。"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ---------------------------------------------------------------- 卸载
Section "Uninstall"
  ; 停止可能运行的实例
  nsExec::ExecToLog 'taskkill /F /IM Sentinel-Ccufo.exe'

  ; 清理所有 Sentinel 写入的防火墙规则，避免留下残留防护影响系统
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="Block SMB ALL inbound"'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="SMB LAN Only"'
  nsExec::ExecToLog 'netsh advfirewall firewall set rule group="文件和打印机共享" new enable=Yes'

  ; 删除自启动项
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${APP}"

  ; 删除文件
  Delete "$INSTDIR\Sentinel-Ccufo.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"

  ; 删除快捷方式
  Delete "$SMPROGRAMS\${APP}\${APP}.lnk"
  Delete "$SMPROGRAMS\${APP}\卸载\卸载.lnk"
  RMDir "$SMPROGRAMS\${APP}\卸载"
  RMDir "$SMPROGRAMS\${APP}"
  Delete "$DESKTOP\${APP}.lnk"

  ; 清理注册表
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"
  DeleteRegKey HKLM "Software\${APP}"
SectionEnd