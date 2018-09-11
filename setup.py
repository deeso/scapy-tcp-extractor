#!/usr/bin/env python3
from setuptools import setup, find_packages
# configure the setup to install from specific repos and users

DESC = 'Reassemble TCP Data Streams Using Scapy'
setup(name='scapy-tcp-extractor',
      version='1.0',
      description=DESC,
      author='adam pridgen',
      author_email='dso@thecoverofnight.com',
      install_requires=['scapy', ],
      packages=find_packages('src'),
      package_dir={'': 'src'},
      dependency_links=[],
      )
