import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="fathomapi",
    version="0.20.3",
    author="Stephen Poole",
    author_email="stephen@melon.software",
    description="A library and toolkit for running microservice APIs in AWS Lambda",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/biometrixtech/fathomapi",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Proprietary",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'aws-xray-sdk==2.3.0',
        'Flask==1.0.2',
        'python-jose==3.0.1',
        'semver==2.8.1',
        'requests==2.21.0'
    ],
    package_data={'fathomapi': ['data/auth/fathom.jwks']},
)
