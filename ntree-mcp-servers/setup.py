"""
NTREE MCP Servers Setup
Installation configuration for NTREE Model Context Protocol servers
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="ntree-mcp-servers",
    version="2.1.0",
    description="NTREE MCP servers for Claude Code penetration testing on Raspberry Pi",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="NTREE Project",
    author_email="ntree@example.com",
    url="https://github.com/YOUR_USERNAME/ntree-mcp-servers",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "mcp>=1.0.0",
        "pydantic>=2.0.0",
        "python-nmap>=0.7.1",
        "ipaddress",
        "xmltodict>=0.13.0",
        "aiofiles>=23.0.0",
        "typing-extensions>=4.0.0",
        "netifaces>=0.11.0",  # For local IP detection (self-IP protection)
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "ruff>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ntree-scope=ntree_mcp.scope:main",
            "ntree-scan=ntree_mcp.scan:main",
            "ntree-enum=ntree_mcp.enum:main",
            "ntree-vuln=ntree_mcp.vuln:main",
            "ntree-report=ntree_mcp.report:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="penetration-testing security mcp claude-code raspberry-pi",
    project_urls={
        "Documentation": "https://github.com/YOUR_USERNAME/ntree-mcp-servers/docs",
        "Source": "https://github.com/YOUR_USERNAME/ntree-mcp-servers",
        "Tracker": "https://github.com/YOUR_USERNAME/ntree-mcp-servers/issues",
    },
)
