#!/usr/bin/env python

from setuptools import setup

with open('README.md') as readme_file:
    readme = readme_file.read()

with open('dadb/VERSION') as f:
    version = f.read().lstrip().rstrip()

setup(
    name='dadb',
    version=version,
    author='Netherlands Forensic Institute',
    description="Data Analysis DataBase",
    url='https://github.com/NetherlandsForensicInstitute/dadb',
    long_description=readme+"\n\n",
    packages=['dadb'],
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 3 :: Only',
        'Intended Audience :: Science/Research',
        'Topic :: Scientific/Engineering :: Information Analysis',
        'Environment :: Console'
        ],
    keywords='forensics analysis sqlite',
    install_requires=[
        'tqdm',
        'python-dateutil',
        'apsw'
    ],
    zip_safe=False,
    package_data={
        # include the VERSION file
        'dadb': ['VERSION']
    }
)
