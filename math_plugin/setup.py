from setuptools import setup, find_packages

setup(
    name="tealer-math-plugin",
    description="tealer plugin for detecting paths with missing rekeyTo in stateless contracts.",
    author="Peter Ince",
    version="0.0.1",
    packages=find_packages(),
    python_requires=">=3.6",
    install_requires=["tealer"],
    entry_points={
        "teal_analyzer.plugin": "mathploit_plugin=tealer_math_plugin:make_plugin",
    },
)
