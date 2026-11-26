import os
project_home = "/home/YOUR_PYTHONANYWHERE_USERNAME/kuro_panel"
if project_home not in os.sys.path:
    os.sys.path.insert(0, project_home)

os.environ["KURO_SECRET_KEY"] = "REPLACE_WITH_A_LONG_RANDOM_SECRET"
from app import app as application
