from setuptools import setup, find_packages

setup(
    name = 'WDATPAPISample',
    version = '1.0.0',
    url = 'https://github.com/JohnLaTwC/WDATPAPI',
    author = 'John Lambert',
    author_email = 'johnla@microsoft.com',
    description = 'Python / Jupyter sample for interacting with Windows Defender ATP APIs',
    packages = find_packages(),    
    install_requires = [ 'ipython>=7.0.1',
                        'matplotlib>=3.0.0',
                        'pandas>=0.23.4',
                        'requests>=2.19.1',
                        'setuptools>=40.4.3'],
)
