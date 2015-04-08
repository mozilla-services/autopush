import io
import os

from autopush import __version__
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, 'README.rst'), encoding='utf8') as f:
    README = f.read()
with io.open(os.path.join(here, 'CHANGELOG.rst'), encoding='utf8') as f:
    CHANGES = f.read()

extra_options = {
    "packages": find_packages(),
}


setup(name="AutoPush",
      version=__version__,
      description='SimplePush Server',
      long_description=README + '\n\n' + CHANGES,
      classifiers=["Topic :: Internet :: WWW/HTTP",
                   "Programming Language :: Python :: Implementation :: PyPy",
                   'Programming Language :: Python',
                   "Programming Language :: Python :: 2",
                   "Programming Language :: Python :: 2.7"
                   ],
      keywords='push',
      author="Ben Bangert",
      author_email="ben@groovie.org",
      url='http:///',
      license="MPL2",
      test_suite="nose.collector",
      include_package_data=True,
      zip_safe=False,
      tests_require=['nose', 'coverage', 'mock>=1.0.1', 'moto>=0.4.1'],
      install_requires=[
          "twisted>=15.0",
          "autobahn>=0.10.1",
          "cryptography>=0.7.2",
          "cyclone>=1.1",
          "boto>=2.36",
          "txstatsd>=1.0.0",
          "configargparse>=0.9.3",
          "apns>=2.0.1",
          "gcm-client>=0.1.4",
          "pyopenssl>=0.14",
          "service-identity>=14.0.0",
          "raven>=0.5.2",
          "datadog>=0.2.0",
          "eliot>=0.6.0",
      ],
      entry_points="""
      [console_scripts]
      autopush = autopush.main:connection_main
      autoendpoint = autopush.main:endpoint_main
      autonode = autopush.main:unified_main
      autokey = autokey:main
      """,
      **extra_options
      )
