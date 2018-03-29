from setuptools import setup, find_packages

github = 'https://github.com/jmwri/simplejwt'
version = '0.1.0'

setup(
    name='simplejwt',
    packages=find_packages(),
    version=version,
    license='MIT',
    python_requires='>=3.6, <4',
    description='A dead simple JWT library',
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
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
    ],
    setup_requires=['pytest-runner'],
    install_requires=[
        'typing',
    ],
    tests_require=[
        'pytest',
    ],
    extras_require={
        'test': [
            'coverage', 'tox', 'pytest'
        ]
    }
)
