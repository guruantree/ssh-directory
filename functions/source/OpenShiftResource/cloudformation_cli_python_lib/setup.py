"""Support library to enable Python-based CloudFormation resource types"""
from setuptools import setup

setup(
    name="cloudformation-cli-python-lib",
    version="2.0.0",
    description=__doc__,
    author="Amazon Web Services",
    author_email="aws-cloudformation-developers@amazon.com",
    url="https://github.com/aws-cloudformation/aws-cloudformation-rpdk-python-plugin/",
    packages=["cloudformation_cli_python_lib"],
    # package_data -> use MANIFEST.in instead
    include_package_data=True,
    zip_safe=True,
    python_requires=">=3.6",
    install_requires=["boto3>=1.10.20", 'dataclasses;python_version<"3.7"'],
    license="Apache License 2.0",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Topic :: Software Development :: Build Tools",
        "Topic :: Software Development :: Code Generators",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    keywords="Amazon Web Services AWS CloudFormation",
)
