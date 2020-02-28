from setuptools import setup, find_packages
from os import path
import sys

import sys
if sys.version_info < (3, 6):
    sys.exit('Sorry, Python < 3.6 is not supported')


lpath = path.abspath(path.dirname(__file__))

with open(path.join(lpath, 'README.md'), encoding='utf-8') as fh:
    long_description = fh.read()

with open(path.join(lpath, 'requirements.txt'), "r") as fh:
    reqs = [r for r in fh.read().splitlines() if len(r) > 0]

setup(
    name='napalm-gaia',
    version='0.0.7',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=find_packages('napalm_gaiaos'),
    package_dir={'': 'napalm_gaiaos'},
    url='https://github.com/remingu/napalm-gaia',
    license='Apache 2.0',
    author='Daniel Schlifka(remingu), mbtathcx',
    author_email='remingu@techturn.de',
    description='napalm driver plugin for checkpoint gaia-os',
    install_requires=reqs,
    keywords='development napalm checkpoint gaia ',
    python_requires='>=3.5',
    project_urls={
        'Bug Reports': 'https://github.com/remingu/napalm-gaia/issues',
        'Source': 'https://github.com/remingu/napalm-gaia',
    },
)

