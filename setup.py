from setuptools import setup

setup(
    name='homu',
    version='0.1.0',
    author='Barosl Lee',
    url='https://github.com/barosl/homu',
    description='Homu is a continuous integration service bot for GitHub and Buildbot.',

    packages=['homu'],
    install_requires=[
        'github3.py',
        'toml',
        'Jinja2',
        'requests',
        'bottle',
        'waitress',
    ],
    package_data={
        'homu': [
            'html/*.html',
        ],
    },
    entry_points={
        'console_scripts': [
            'homu=homu.main:main',
        ],
    },
    zip_safe=False,
)
