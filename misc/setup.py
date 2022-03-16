#!/usr/bin/env python3

import os, subprocess, glob
from setuptools import setup, find_packages

here = os.path.dirname(os.path.realpath(__file__))
wdir = here
desc_str=''
if os.path.exists(wdir):
    git_hash = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], cwd=wdir)

    # use the git hash in the setup
    desc_str = 'git hash [ %s ]' % git_hash.strip()

dependencies = [
]

setup(
    name='acc-bpf',
    install_requires=dependencies,
    version='0.1',
    description=desc_str,
    packages=find_packages(),
    license='Apache 2.0',
    author='',
    author_email='',
    scripts=glob.glob("bin/*.py"),
    maintainer='',
    maintainer_email='',
    classifiers=[
        'Intended Audience :: Developers',
        'Operating System :: Linux',
        'Programming Language :: Python',
    ],

)
