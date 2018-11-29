from setuptools import setup, find_packages

setup(
    name = 'WDATPAPISample',
    version = '1.0.0',
    url = 'https://github.com/JohnLaTwC/WDATPAPI',
    author = 'John Lambert',
    author_email = 'johnla@microsoft.com',
    description = 'Python / Jupyter sample for interacting with Windows Defender ATP APIs',
    packages = find_packages(),    
    install_requires = [ 'ipython>=5.5.0',
                        'matplotlib>=2.1.1',
                        'pandas>=0.21.1',
                        'holoviews>=1.10.8',
                        'requests>=2.18.4',
                        'setuptools>=38.2.4'],
)
