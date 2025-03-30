import sys
import os

# Add the application directory to the Python path
INTERP = os.path.expanduser("/usr/local/bin/python3")
if sys.executable != INTERP:
    os.execl(INTERP, INTERP, *sys.argv)

sys.path.append(os.getcwd())

# Import the app from your main file
from app import app as application 