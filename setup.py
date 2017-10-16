import io
import os

from autopush import __version__
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, 'README.md'), encoding='utf8') as f:
    README = f.read()
with io.open(os.path.join(here, 'CHANGELOG.md'), encoding='utf8') as f:
    CHANGES = f.read()

WITH_RUST = os.environ.get('WITH_RUST', 'true').lower() not in ('false', '0')

extra_options = {
    "packages": find_packages(),
}
if WITH_RUST:
    extra_options.update(
        setup_requires=['snaek'],
        install_requires=['snaek'],
        snaek_rust_modules=[
            ('autopush_rs._native', 'autopush_rs/'),
        ],
    )


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
      entry_points="""
      [console_scripts]
      autopush = autopush.main:ConnectionApplication.main
      autoendpoint = autopush.main:EndpointApplication.main
      autopush_rs = autopush.main:RustConnectionApplication.main
      autokey = autokey:main
      endpoint_diagnostic = autopush.diagnostic_cli:run_endpoint_diagnostic_cli
      drop_users = autopush.scripts.drop_user:drop_users
      [nose.plugins]
      object-tracker = autopush.noseplugin:ObjectTracker
      """,
      **extra_options
      )
