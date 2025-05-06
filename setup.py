from setuptools import setup, find_packages

setup(
    name="adaptive-security-mesh",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "pytest>=7.0.0",
        "pytest-asyncio>=0.21.0",
        "pytest-cov>=4.1.0",
        "pyyaml>=6.0.1",
        "cryptography>=41.0.0",
        "python-jose>=3.3.0",
        "aiohttp>=3.8.0",
        "python-multipart>=0.0.6",
        "pydantic>=2.0.0",
        "typing-extensions>=4.5.0"
    ],
    python_requires=">=3.8",
) 