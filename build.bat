@echo off
:: ────────────────────────────────────────────────────
:: TEA Forensic Collector - EXE Build Script
:: Requirements: Python 3.8+, PyInstaller
:: Run: build.bat  (proje root'undan calistirin)
:: Output: dist\TEADFIR.exe
:: ────────────────────────────────────────────────────

echo.
echo  [TEA FORENSIC COLLECTOR - BUILD SCRIPT]
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Python not found. Install Python 3.8+ first.
    pause
    exit /b 1
)

:: Install/update dependencies
echo  [*] Installing dependencies...
python -m pip show pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    python -m pip install pyinstaller --quiet
)

:: yara-python — yoksa uyar ama build'i durdurma
python -m pip show yara-python >nul 2>&1
if %errorlevel% neq 0 (
    echo  [*] Installing yara-python...
    python -m pip install yara-python --quiet
    if %errorlevel% neq 0 (
        echo  [!] yara-python kurulamadi. YARA tarama ozelligi devre disi olacak.
        echo  [!] Build devam ediyor...
    )
)

:: Clean previous build artifacts
echo  [*] Cleaning previous build...
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build
if exist src\__pycache__ rmdir /s /q src\__pycache__

:: Build EXE
echo  [*] Building EXE...

python -m PyInstaller ^
    --onefile ^
    --console ^
    --name "TEADFIR" ^
    --uac-admin ^
    --version-file="%~dp0version_info.txt" ^
    --hidden-import=winreg ^
    --hidden-import=ctypes ^
    --hidden-import=subprocess ^
    --hidden-import=yara ^
    --add-data "ioc;ioc" ^
    --add-data "yara_rules;yara_rules" ^
    --exclude-module=tkinter ^
    --exclude-module=matplotlib ^
    --exclude-module=numpy ^
    --exclude-module=PIL ^
    --distpath dist ^
    --workpath build ^
    --specpath build ^
    src\main.py

if %errorlevel% neq 0 (
    echo  [!] Build FAILED.
    pause
    exit /b 1
)

:: Cleanup build artifacts
if exist build rmdir /s /q build

echo.
echo  [+] Build successful!
echo  [+] Output: dist\TEADFIR.exe
echo.

for %%A in (dist\TEADFIR.exe) do echo  [+] Size: %%~zA bytes

echo.
echo  USAGE:
echo    TEADFIR.exe                         (collect to current dir)
echo    TEADFIR.exe -o C:\evidence          (output directory)
echo    TEADFIR.exe --json                  (also save raw JSON)
echo    TEADFIR.exe --vt-key YOUR_API_KEY   (VirusTotal integration)
echo    TEADFIR.exe --yara-rules C:\rules   (custom YARA rules dir)
echo    TEADFIR.exe --no-elevate            (skip UAC prompt)
echo.
pause
