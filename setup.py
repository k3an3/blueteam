from setuptools import setup, find_packages

setup(
    name='blueteam',
    version='0.1',
    packages=find_packages(),
    url='',
    license='',
    author="Keane O'Kelley",
    author_email='keane.m.okelley@gmail.com',
    description='',
    install_requires=[
        'braceexpand',
        'colorful',
        'paramiko',
        'psutil'
    ],
    entry_points={
        'console_scripts': [
            'blueteam=blueteam:cli',
        ]
    },
)
