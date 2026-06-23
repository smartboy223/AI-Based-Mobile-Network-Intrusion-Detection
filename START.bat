@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo ============================================
echo AI-Based Mobile Network Intrusion Detection
echo Unified launcher (single window)
echo ============================================
echo.

REM ---------- Prerequisite checks ----------
where node >nul 2>nul
if errorlevel 1 (
  echo ERROR: Node.js not found. Install from https://nodejs.org/
  pause
  exit /b 1
)

where python >nul 2>nul
if errorlevel 1 (
  echo ERROR: Python not found. Install from https://www.python.org/
  echo        Make sure you ticked "Add Python to PATH" during install.
  pause
  exit /b 1
)

REM Kill any prior instances so we don't fight for ports
taskkill /F /IM node.exe >nul 2>&1
taskkill /F /IM python.exe >nul 2>&1
timeout /t 1 >nul

REM ---------- Node deps ----------
if not exist "node_modules" (
  echo [setup] Installing Node dependencies...
  call npm install
  if errorlevel 1 (
    echo ERROR: npm install failed
    pause
    exit /b 1
  )
)

REM ---------- Python virtual environment ----------
REM .venv/ keeps the project's pip installs isolated from the system Python
REM and from other projects on this machine. It's recreated automatically
REM on first run, and survives moves to a new PC as long as the new PC has
REM Python on PATH (the venv is rebuilt against THAT Python). The folder
REM is .gitignored — it's a build artefact.
set "VENV_DIR=%~dp0.venv"
set "VENV_PY=%VENV_DIR%\Scripts\python.exe"

if not exist "%VENV_PY%" (
  echo [setup] Creating Python virtual environment at .venv\
  python -m venv "%VENV_DIR%"
  if errorlevel 1 (
    echo ERROR: Could not create .venv. Make sure the Python "venv" module is installed.
    echo        On some custom Python builds you may need to run:  python -m ensurepip
    pause
    exit /b 1
  )
)

REM ---------- Python deps inside the venv ----------
REM We *don't* trust a flag file alone — instead we actually try to import
REM the critical packages from inside the venv. If that fails (fresh venv,
REM partial install, deleted package, stale .python_deps_installed sentinel
REM left over from a previous system-Python install), we re-run pip install
REM and only write the sentinel after a clean import probe.
"%VENV_PY%" -c "import joblib, fastapi, numpy, pandas, sklearn" >nul 2>nul
if errorlevel 1 (
  echo [setup] Installing Python dependencies into .venv from backend\requirements.txt ...
  "%VENV_PY%" -m pip install --upgrade pip
  "%VENV_PY%" -m pip install -r backend\requirements.txt
  if errorlevel 1 (
    echo.
    echo ERROR: pip install failed.
    echo Common causes:
    echo   - Network / proxy issue blocking PyPI
    echo   - Missing VC++ Redistributable for TensorFlow ^(install from Microsoft^)
    echo   - Old CPU lacking AVX2 ^(set MNIDS_DISABLE_TF=1 in backend\.env^)
    echo.
    pause
    exit /b 1
  )
  REM Verify the install actually worked before writing the sentinel.
  "%VENV_PY%" -c "import joblib, fastapi, numpy, pandas, sklearn" >nul 2>nul
  if errorlevel 1 (
    echo.
    echo ERROR: pip install reported success but the venv still cannot import
    echo        joblib / fastapi / numpy / pandas / sklearn. The venv may be
    echo        corrupted — delete the .venv folder and re-run START.bat.
    pause
    exit /b 1
  )
  echo. > .python_deps_installed
)

REM Make launch.mjs and any child process use the venv's Python (not system).
set "PYTHON=%VENV_PY%"

REM ---------- .env bootstrap ----------
if not exist "backend\.env" (
  if exist "backend\.env.example" (
    echo [setup] Creating backend\.env from .env.example
    copy /Y "backend\.env.example" "backend\.env" >nul
  )
)

call :prompt_env_key "DEEPSEEK_API_KEY" "DeepSeek API key for the AI assistant"
call :prompt_env_key "VIRUSTOTAL_API_KEY" "VirusTotal API key for live reputation lookups"

REM ---------- Launch ----------
REM launch.mjs handles: build (if stale), spawn ML + Web, health-gate, open browser
node launch.mjs

pause
exit /b 0

:prompt_env_key
set "ENV_KEY=%~1"
set "ENV_LABEL=%~2"
set "ENV_VALUE="

if not exist "backend\.env" exit /b 0

for /f "usebackq tokens=1* delims==" %%A in ("backend\.env") do (
  if /I "%%A"=="%ENV_KEY%" set "ENV_VALUE=%%B"
)

set "NEEDS_KEY=0"
if "%ENV_VALUE%"=="" set "NEEDS_KEY=1"
if /I "%ENV_VALUE%"=="YOUR_API_KEY_HERE" set "NEEDS_KEY=1"
if /I "%ENV_VALUE%"=="YOUR_KEY_HERE" set "NEEDS_KEY=1"
if /I "%ENV_VALUE%"=="your_virustotal_api_key_here" set "NEEDS_KEY=1"
if /I "%ENV_VALUE%"=="your_deepseek_api_key_here" set "NEEDS_KEY=1"

if "%NEEDS_KEY%"=="1" (
  echo.
  echo [setup] Optional: %ENV_LABEL%
  set /p "USER_KEY=Paste key now or press Enter to skip: "
  if not "!USER_KEY!"=="" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='backend\\.env'; $k='%ENV_KEY%'; $v=$env:USER_KEY; $text=Get-Content -Raw $p; if ($text -match ('(?m)^' + [regex]::Escape($k) + '=')) { $text=[regex]::Replace($text, '(?m)^' + [regex]::Escape($k) + '=.*$', $k + '=' + $v) } else { $text += \"`r`n$k=$v`r`n\" }; Set-Content -NoNewline -Path $p -Value $text"
    echo [setup] Saved %ENV_KEY% to backend\.env
  ) else (
    echo [setup] Skipping %ENV_KEY%. Related features stay disabled.
  )
)
exit /b 0
