import os
import sys  # ##DWM::

from setuptools import find_packages, setup

with open('README.rst') as readme_file:
    readme = readme_file.read()


def prerelease_local_scheme(version):
    """
    Return local scheme version unless building on master in CircleCI.

    This function returns the local scheme version number
    (e.g. 0.0.0.dev<N>+g<HASH>) unless building on CircleCI for a
    pre-release in which case it ignores the hash and produces a
    PEP440 compliant pre-release version number (e.g. 0.0.0.dev<N>).
    """
    from setuptools_scm.version import get_local_node_and_date

    sys.stderr.write('HERE: %r\n' % [os.getenv('GITHUB_REF')])  # ##DWM::
    if os.getenv('GITHUB_REF') == 'refs/heads/main':
        return ''
    else:
        return get_local_node_and_date(version)


setup(
    name='girder_client_mount',
    use_scm_version={'local_scheme': prerelease_local_scheme},
    setup_requires=['setuptools-scm'],
    author='Kitware, Inc.',
    author_email='kitware@kitware.com',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    description='Mount a girder server via fuse',
    install_requires=[
        'cachetools',
        'fusepy',
        'girder-client',
        'httpio',
        'python-dateutil',
    ],
    license='Apache Software License 2.0',
    long_description=readme,
    long_description_content_type='text/x-rst',
    include_package_data=True,
    keywords='girder, fuse, girder-client',
    packages=find_packages(exclude=['test', 'test.*']),
    url='https://github.com/manthey/girder-client-mount',
    zip_safe=False,
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'girder-client-mount = girder_client_mount:main',
        ]
    }
)
