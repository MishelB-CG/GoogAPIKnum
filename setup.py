from setuptools import setup, find_packages

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="GoogAPIKnum",
    version="0.1.0",
    description="Google API key access checker across various Google APIs.",
    long_description=(
        "A command-line tool for testing Google API keys against multiple Google services, "
        "including a headless Maps JavaScript API check using Playwright."
    ),
    long_description_content_type="text/plain",
    author="MishelB",
    url="https://github.com/MishelB-CG/GoogAPIKnum",
    packages=find_packages(),
    install_requires=requirements,
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            # command name = package.module:function
            "googapi-knum = googapi_knum.cli:run",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    include_package_data=True,
    zip_safe=False,
)
