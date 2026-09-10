@echo off
REM Setup and run script for Airlock Partner Consulting Tool Kit (app.py)
REM Run this from wherever you've placed the project folder — it locates
REM itself automatically, no hardcoded path required.
cd /d "%~dp0"

REM Fail fast with a clear message if app.py isn't actually here — e.g.
REM if this .bat file got copied out on its own without the rest of the
REM project files.
if not exist "app.py" (
    echo.
    echo ERROR: app.py was not found in this folder:
    echo   %cd%
    echo.
    echo Make sure run.bat sits in the same folder as app.py,
    echo requirements.txt, and the templates\ folder ^(i.e. extract the
    echo whole project together, don't move run.bat by itself^).
    echo.
    pause
    exit /b 1
)

REM Create virtual environment if it doesn't already exist
if not exist "venv\" (
    echo Creating virtual environment...
    python -m venv venv
) else (
    echo Virtual environment already exists, skipping creation.
)

REM Activate the virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install requirements
if exist "requirements.txt" (
    echo Installing requirements...
    pip install -r requirements.txt
) else (
    echo No requirements.txt found, skipping install.
)

REM Launch the app
echo Launching app.py...
python app.py
pause
