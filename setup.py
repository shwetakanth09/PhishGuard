from setuptools import setup, find_packages
import platform
import sys

# Read requirements
with open("requirements.txt", "r") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

# Platform-specific requirements
linux_requirements = []
windows_requirements = []
macos_requirements = []

if platform.system() == "Linux":
    requirements.extend(linux_requirements)
elif platform.system() == "Windows":
    requirements.extend(windows_requirements)
elif platform.system() == "Darwin":
    requirements.extend(macos_requirements)

setup(
    name="cybershield",
    version="1.0.0",
    author="Aditya Sharma",
    author_email="adityaiit687@gmail.com",
    description="AI-powered cybersecurity toolkit: Phishing Detection + Vulnerability Scanner",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/aditya226-sharma/cybershield",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
        ],
        "rich": [
            "rich>=13.0.0",
        ],
        "whois": [
            "python-whois>=0.8.0",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Environment :: Web Environment",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "cybershield=cybershield.__main__:main",
        ],
    },
    project_urls={
        "Bug Tracker": "https://github.com/aditya226-sharma/cybershield/issues",
        "Documentation": "https://github.com/aditya226-sharma/cybershield#readme",
        "Source Code": "https://github.com/aditya226-sharma/cybershield",
    },
)
