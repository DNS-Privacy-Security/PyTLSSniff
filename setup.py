import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="PyTLSSniff",
    version="0.0.1",
    author="M4t7e",
    description="Python TLS handshake sniffer to extract domain names",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/DNS-Privacy-Security/PyTLSSniff",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)