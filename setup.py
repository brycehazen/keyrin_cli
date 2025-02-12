from setuptools import setup

setup(
    name="keyring_cli",
    version="1.0",
    py_modules=["keyring_cli"],
    install_requires=[
        "keyring",
        "cryptography",
        "pywin32",
        "toml",  
    ],
    entry_points={
        "console_scripts": [
            "keyring-cli=keyring_cli:main",
        ],
    },
)
