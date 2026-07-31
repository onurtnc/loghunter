from setuptools import find_packages, setup

setup(
    name="loghunter",
    version="1.0.0",
    description="Sigma benzeri kurallarla calisan hafif log tespit motoru (mini SIEM)",
    packages=find_packages(exclude=["tests"]),
    include_package_data=True,
    package_data={"": ["rules/**/*.yml"]},
    python_requires=">=3.8",
    entry_points={"console_scripts": ["loghunter=loghunter.cli:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
