from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="spaider",
    version="1.0.0",
    author="SPAIDER Team",
    description="SPAIDER — AI-Powered Cybersecurity Command Platform (Linux CLI & Framework)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/spaider-ai/spaider",
    packages=find_packages(where="backend"),
    package_dir={"": "backend"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.111.0",
        "uvicorn>=0.29.0",
        "rich>=13.7.0",
        "pydantic>=2.7.0",
        "pydantic-settings>=2.2.0",
        "httpx>=0.27.0",
        "python-dotenv>=1.0.0",
        "structlog>=24.1.0",
    ],
    extras_require={
        "full": [
            "sqlalchemy>=2.0.30",
            "aiosqlite>=0.20.0",
            "python-nmap>=0.7.1",
            "openai>=1.30.0",
            "anthropic>=0.28.0",
            "langchain>=0.2.1",
        ]
    },
    entry_points={
        "console_scripts": [
            "spaider=app.cli:main",
        ],
    },
    scripts=["bin/spaider"],
)
