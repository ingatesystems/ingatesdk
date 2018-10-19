import distutils
import setuptools

PKGNAME = 'ingatesdk'

with open("README.md", "r") as fh:
    long_description = fh.read()

try:
    distutils.dir_util.remove_tree('dist')
except:
    pass
try:
    distutils.dir_util.remove_tree('build')
except:
    pass
try:
    distutils.dir_util.remove_tree('%s.egg-info' % PKGNAME)
except:
    pass

setuptools.setup(
    name=PKGNAME,
    version='1.0.5',
    author='Ingate Systems AB',
    author_email='fuegodev@ingate.com',
    description='Ingate Python SDK',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://ingate.com',
    keywords=['ingate', 'sdk', 'api'],
    packages=['ingate'],
    include_package_data=True,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
