import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt') as fh:
    install_requires = fh.read()

setuptools.setup(
    name="PyTLSSniff",
    version="0.0.4",
    author="M4t7e",
    license='MIT License',
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
    install_requires=install_requires,
    platforms=('Any'),
    entry_points={'console_scripts': [
        'pytlssniff = pytlssniff.cli:cli',
    ]},
)
