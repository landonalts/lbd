@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

set VCVARS=
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSPATH=%%i
if not defined VSPATH (
  echo [!] Visual Studio with C++ tools not found.
  exit /b 1
)
set VCVARS=%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat

if not exist minhook (
  git clone --depth 1 --branch v1.3.4 https://github.com/TsudaKageyu/minhook || exit /b 1
)

if not exist out mkdir out

call "%VCVARS%" x64 >nul || exit /b 1
cl /nologo /LD /O2 /EHsc src\hide.cpp /Iminhook\include /link minhook\build\minhook.x64.lib /OUT:out\hide64.dll || exit /b 1
cl /nologo /O2 /EHsc src\ldbwatch.cpp /Fo:out\ /link user32.lib dwmapi.lib /OUT:out\ldbwatch.exe || exit /b 1

call "%VCVARS%" x86 >nul || exit /b 1
cl /nologo /LD /O2 /EHsc src\hide.cpp /Iminhook\include /link minhook\build\minhook.x86.lib /OUT:out\hide32.dll || exit /b 1
cl /nologo /O2 /EHsc src\inject32.cpp /Fo:out\ /OUT:out\inject32.exe || exit /b 1

copy /y config\hide.cfg out\hide.cfg >nul
echo.
echo built into out\ — run out\ldbwatch.exe as administrator
