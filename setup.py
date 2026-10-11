from setuptools import setup, find_packages

setup(
    name="roguebyte",
    version="1.0.0",
    description="ROGUEBYTE - Professional Cybersecurity & Network Defense Suite",
    author="ROGUEBYTE Security Engineering",
    packages=find_packages(),
    py_modules=["app"],
    install_requires=[
        "PySide6>=6.6.0",
        "psutil>=5.9.8",
        "fastapi>=0.110.0",
        "uvicorn[standard]>=0.29.0",
        "pydantic>=2.6.0",
        "requests>=2.31.0",
        "pytest>=8.0.0",
        "pyinstaller>=6.5.0",
    ],
    entry_points={
        "console_scripts": [
            "roguebyte=app:main",
        ],
    },
    python_requires=">=3.10",
)
