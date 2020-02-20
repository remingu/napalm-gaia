''setup.py file.''
import uuid

from setuptools import setup, find_packages
try:
    from pip._internal.req import parse_requirements
except ImportError:
    from pip.req import parse_requirements

__author__ = 'emingu, mbtathcx'

install_reqs = parse_requirements('requirements.txt', session=uuid.uuid1())
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name='napalm-gaiaos',
    version='0.0.1',
    packages=find_packages(),
    author='remingu, mbtathcx',
    author_email='',
    description='Network Automation and Programmability Abstraction Layer (NAPALM) Checkpoint Gaia driver',
    long_description='Gaia driver support for Napalm network automation.',
    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
    ],
    url='https://github.com/ixs/napalm-procurve',
    include_package_data=True,
    zip_safe=False,
    install_requires=reqs,
)