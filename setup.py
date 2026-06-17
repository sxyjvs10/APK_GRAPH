from setuptools import setup, find_packages

setup(
    name="apkgraph",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "androguard",
        "networkx",
        "rich",
        "click",
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
    description="Android Attack Surface Intelligence Platform",
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
