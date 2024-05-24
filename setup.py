from setuptools import setup, find_packages


def get_requirements():
    with open("requirements.txt") as f:
        requirements =  f.read().splitlines()
    return requirements


setup(
    name="PLEASE",
    version="0.1",
    packages=find_packages(),
    include_package_data=True,
    install_requires=get_requirements(),
    python_requires=">=3.7",
    entry_points='''
        [console_scripts]
        pls=please.main:main
    '''
)