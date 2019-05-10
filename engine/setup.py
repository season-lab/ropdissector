#! /usr/bin/env python
from setuptools import setup
from setuptools import find_packages

__version__ = '0.1.0'

with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    author           = 'Andrea Salvati',
    author_email     = 'andrea.slvt94@gmail.com',
    name             = 'ROPDissector',
    description      = 'A framework for static analysis of ROP code',
    long_description = readme,
    license          = license,
    install_requires = [
        'capstone>=4.0.1',
        'pefile',
        'enum34',
        'networkx',
        'unicorn',
        'graphviz',
        'pydot'
    ],
    packages         = find_packages(),
    url              = 'http://github.com/season-lab/ropdissector',
    version          = __version__,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Topic :: Scientific/Engineering :: Information Analysis',
        'Topic :: Utilities',
        'Topic :: Security',
    ],
)
