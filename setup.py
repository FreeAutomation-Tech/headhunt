from setuptools import setup, find_packages

setup(
    name="headhunt",
    version="1.0.0",
    packages=find_packages("src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.28",
    ],
    entry_points={
        "console_scripts": [
            "headhunt=src.cli:main",
        ],
    },
)
