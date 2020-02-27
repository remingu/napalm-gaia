from distutils.core import setup
import sys

import sys
if sys.version_info < (3,6):
    sys.exit('Sorry, Python < 3.6 is not supported')

setup(
    name='napalm-gaia',
    version='0.0.2rc2',
    packages=['napalm_gaiaos', 'napalm_gaiaos.helper'],
    url='',
    license='',
    author='remingu, mbtathcx',
    author_email='',
    description='',
    install_requires=[
       "napalm >= 2.5.0"]
)
