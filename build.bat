@echo off
:: ────────────────────────────────────────────────────
:: TEA Forensic Collector - EXE Build Script
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

:: Install/update PyInstaller
echo  [*] Installing dependencies...
python -m pip show pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    python -m pip install pyinstaller --quiet
)

:: yara-python — pre-built wheel dene, olmazsa devam et
python -c "import yara_x" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [*] Trying yara-python pre-built wheel...
    python -m pip install yara-x --quiet 2>&1
    if %errorlevel% neq 0 (
        echo  [!] yara-python pre-built wheel bulunamadi.
        echo  [!] Python %PYTHON_VERSION% icin C++ Build Tools gerekiyor.
        echo  [!] YARA tarama ozelligi bu build'de devre disi olacak.
        echo  [!] Cozum: https://visualstudio.microsoft.com/visual-cpp-build-tools/
        echo  [!] Build devam ediyor...
    ) else (
        echo  [+] yara-python kuruldu.
    )
) else (
    echo  [+] yara-python zaten kurulu.
)

:: Clean
echo  [*] Cleaning previous build...
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build
if exist src\__pycache__ rmdir /s /q src\__pycache__

:: Build EXE — add-data için mutlak path kullan
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
    --hidden-import=yara_x ^
    --add-data "%~dp0ioc;ioc" ^
    --add-data "%~dp0yara_rules;yara_rules" ^
    --exclude-module=tkinter ^
    --exclude-module=matplotlib ^
    --exclude-module=numpy ^
    --exclude-module=PIL ^
    --distpath "%~dp0dist" ^
    --workpath "%~dp0build" ^
    --specpath "%~dp0build" ^
    "%~dp0src\main.py"

if %errorlevel% neq 0 (
    echo  [!] Build FAILED.
    pause
    exit /b 1
)

if exist "%~dp0build" rmdir /s /q "%~dp0build"

echo.
echo  [+] Build successful!
echo  [+] Output: dist\TEADFIR.exe
echo.

for %%A in ("%~dp0dist\TEADFIR.exe") do echo  [+] Size: %%~zA bytes

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
