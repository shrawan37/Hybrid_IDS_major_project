import subprocess
import sys
import os

def install_requirements():
    # Ensure setuptools is available for pkg_resources
    try:
        import pkg_resources
    except ImportError:
        print("pkg_resources not found, installing setuptools...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "setuptools"], shell= True)

    required = set()
    
    # Check if requirements.txt exists
    if not os.path.exists("requirements.txt"):
        print("Error: requirements.txt file not found.")
        return

    with open("requirements.txt", "r") as f:
        required = {line.strip() for line in f}

    installed = {pkg.key for pkg in pkg_resources.working_set}
    missing = required - installed

    if missing:
        print(f"Installing missing dependencies: {missing}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
        except subprocess.CalledProcessError as e:
            print(f"Error installing dependencies: {e}")
            return
    else:
        print("All dependencies are already installed.")

# Run the install requirements function
install_requirements()


