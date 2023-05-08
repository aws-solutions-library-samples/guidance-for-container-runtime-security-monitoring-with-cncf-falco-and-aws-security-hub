import setuptools


with open("README.md") as fp:
    long_description = fp.read()


setuptools.setup(
    name="aws_securityhub_falco_ecs_eks_integration",
    #DZ: updated version
    version="0.0.2",

    description="An empty CDK Python app",
    long_description=long_description,
    long_description_content_type="text/markdown",

    author="author",

    package_dir={"": "aws_securityhub_falco_ecs_eks_integration"},
    packages=setuptools.find_packages(where="aws_securityhub_falco_ecs_eks_integration"),

    install_requires=[
        #DZ: updated CDK version
        "aws-cdk.core==1.185.0",
    ],

    python_requires=">=3.7",

    classifiers=[
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers-DevOps",

        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",

        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",

        "Typing :: Typed",
    ],
)
