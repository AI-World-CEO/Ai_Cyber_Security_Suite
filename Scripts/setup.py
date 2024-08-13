from setuptools import setup, find_packages


def readme():
    with open("README.md", "r") as f:
        return f.read()


setup(
    name="Cyber_Ai_Security_Suite",
    version="1.0.0",
    description="A comprehensive AI-driven cybersecurity suite with automated threat response and dynamic encryption.",
    long_description=readme(),
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/Cyber_Ai_Security_Suite",
    packages=find_packages(include=[
        'Data', 'Data.Raw', 'Data.Encrypted', 'Data.Backups', 'Data.Logs', 'Data.Models',
        'Src', 'Src.Encryption', 'Src.Ai', 'Src.Api', 'Src.Ui', 'Src.Utils',
        'Config', 'Docs', 'Tests', 'Scripts', 'Tools', 'Examples', 'Third_Party'
    ]),
    include_package_data=True,
    install_requires=[
        "cryptography",
        "flask",
        "numpy",
        "scikit-learn",
        "tensorflow",
        "pandas",
        "requests",
        "twilio",
        "pyotp"
    ],
    extras_require={
        "dev": [
            "pytest",
            "coverage",
            "sphinx",
            "black",
            "flake8"
        ]
    },
    entry_points={
        "console_scripts": [
            "cyber_ai_security_suite=Src.Scripts.setup:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires='>=3.6',
)
