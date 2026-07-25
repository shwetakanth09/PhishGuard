from setuptools import setup, find_packages

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
    install_requires=[
        "flask>=2.3.0",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "python-whois>=0.8.0",
        "dnspython>=2.4.0",
        "rich>=13.0.0",
        "colorama>=0.4.6",
        "urllib3>=2.0.0",
        "tldextract>=5.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "cybershield=cybershield.__main__:main",
        ],
    },
)
