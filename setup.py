from setuptools import setup, find_packages

setup(
    name="sentryops",
    version="0.1.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "sentryops=scanner.cli:main",
        ],
    },
)
