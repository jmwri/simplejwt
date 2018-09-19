from setuptools import setup, find_packages
import re

with open('simplejwt/__init__.py') as version_file:
    version = re.search(r"""__version__\s+=\s+(['"])(?P<version>.+?)\1""",
                        version_file.read()).group('version')

with open('README.md') as readme:
    long_description = readme.read()

github = 'https://github.com/jmwri/simplejwt'

setup(
    name='simplejwt',
    packages=find_packages(),
    version=version,
    license='MIT',
    description='A dead simple JWT library',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Jim Wright',
    author_email='jmwri93@gmail.com',
    url=github,
    download_url='{github}/archive/{version}.tar.gz'.format(
        github=github, version=version
    ),
    keywords=['python', 'jwt', 'simple', 'simplejwt'],
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Operating System :: OS Independent',
    ],
    install_requires=[
        'typing',
    ],
)
