from setuptools import *

description = 'Python based command line interface tool for plexus.'

setup(
    name='pyplexus',
    version='1.0.2',
    description=description,
    long_description=description,
    url='https://github.com/baliame/pyplexus',
    author='Baliame',
    author_email='akos.toth@cheppers.com',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Utilities',
    ],
    keywords='hmac development library',
    packages=find_packages(),
    install_requires=[
        "boto3",
        "click",
        "http-hmac-python",
        "requests",
    ],
    entry_points={
        'console_scripts': ['plexus.py=pyplexus.pyplexus:cli'],
    }
)
