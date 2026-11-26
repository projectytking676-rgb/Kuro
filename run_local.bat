@echo off
setlocal
cd /d "%~dp0"
if not exist venv (
  py -m venv venv
)
call venv\Scripts\activate
python -m pip install -r requirements.txt
if "%KURO_SECRET_KEY%"=="" (
  echo Set KURO_SECRET_KEY first. Example:
  echo set KURO_SECRET_KEY=your-long-random-secret
  exit /b 1
)
python create_admin.py
python app.py
