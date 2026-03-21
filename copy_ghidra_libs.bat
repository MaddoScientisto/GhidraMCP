@echo off
setlocal EnableExtensions

set "GHIDRA_HOME=%~1"
if not defined GHIDRA_HOME (
    set /p "GHIDRA_HOME=Enter the full path to your Ghidra installation: "
)

if not defined GHIDRA_HOME (
    echo Error: no Ghidra installation path provided.
    exit /b 1
)

set "SOURCE_ROOT=%GHIDRA_HOME%\Ghidra"
if not exist "%SOURCE_ROOT%\Features\Base\lib\Base.jar" (
    echo Error: could not find Ghidra jars under "%SOURCE_ROOT%".
    echo Expected to find "%SOURCE_ROOT%\Features\Base\lib\Base.jar".
    exit /b 1
)

set "DEST_DIR=%~dp0lib"
if not exist "%DEST_DIR%" mkdir "%DEST_DIR%" || exit /b 1

call :copy_file "Features\Base\lib\Base.jar"
call :copy_file "Features\Decompiler\lib\Decompiler.jar"
call :copy_file "Framework\Docking\lib\Docking.jar"
call :copy_file "Framework\Generic\lib\Generic.jar"
call :copy_file "Framework\Project\lib\Project.jar"
call :copy_file "Framework\SoftwareModeling\lib\SoftwareModeling.jar"
call :copy_file "Framework\Utility\lib\Utility.jar"
call :copy_file "Framework\Gui\lib\Gui.jar"

echo.
echo All Ghidra libraries were copied to "%DEST_DIR%".
exit /b 0

:copy_file
set "REL_PATH=%~1"
set "SOURCE_FILE=%SOURCE_ROOT%\%REL_PATH%"
set "DEST_FILE=%DEST_DIR%\%~nx1"

echo Copying %REL_PATH%
copy /Y "%SOURCE_FILE%" "%DEST_FILE%" >nul
if errorlevel 1 (
    echo Error: failed to copy "%SOURCE_FILE%".
    exit /b 1
)
exit /b 0