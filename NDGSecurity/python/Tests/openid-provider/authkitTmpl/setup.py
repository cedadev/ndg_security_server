from setuptools import setup, find_packages
import sys, os

version = '0.1.0'

setup(name='openidprovider',
      version=version,
      description="OpenID Provider",
      long_description="""\
OpenID Provider""",
      classifiers=[], # Get strings from http://www.python.org/pypi?%3Aaction=list_classifiers
      keywords='OpenID',
      author='P J Kershaw',
      author_email='Philip.Kershaw@stfc.ac.uk',
      url='http://proj.badc.rl.ac.uk/ndg/wiki/Security',
      license='Q License',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=True,
      install_requires=[
          # -*- Extra requirements: -*-
          "AuthKit>=0.4,<=0.5",
      ],
      entry_points="""
      # -*- Entry points: -*-
      [authkit.method]
      openidprovider=openidprovider:make_handler
      """,
      )
