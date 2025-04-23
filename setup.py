from setuptools import setup

setup(
    name="keyring_cli",
    version="1.1",  # Incremented version for new functionality
    py_modules=["keyring_cli", "secure_keyring"],  # Added secure_keyring module
    install_requires=[
        "keyring",
        "cryptography", 
        "pywin32",
        "toml",  
    ],
    entry_points={
        "console_scripts": [
            "keyring=keyring_cli:main",
        ],
    },
)
