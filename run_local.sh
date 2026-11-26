#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
if [ -z "${KURO_SECRET_KEY:-}" ]; then
  echo 'Set KURO_SECRET_KEY first: export KURO_SECRET_KEY="$(python -c "import secrets; print(secrets.token_urlsafe(48))")"'
  exit 1
fi
python create_admin.py
python app.py
