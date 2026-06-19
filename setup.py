from setuptools import setup, find_packages

setup(
    name="apkgraph",
    version="2.0.0",
    packages=find_packages(),
    install_requires=[
        "androguard>=3.3.5",
        "networkx>=3.0",
        "rich>=13.0",
        "click>=8.0",
        "pyyaml",
        "jsonschema",
        "lxml",
    ],
    entry_points={
        "console_scripts": [
            "apkgraph=apkgraph.apkgraph:main",
        ],
    },
    author="APKGraph Contributors",
    description="APKGraph v2.0 — Android Attack Surface Intelligence Platform",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/username/apkgraph",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
