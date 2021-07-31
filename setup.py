from setuptools import setup, find_packages

setup(name='yog',
      version='1.0.1',
      description='The Gate and Key',
      url='https://github.com/jmhertlein/yog',
      author='Josh Hertlein',
      author_email='jmhertlein@gmail.com',
      license='AGPLv3',
      packages=find_packages(),
      zip_safe=False,
      install_requires=[
            'pyyaml',
            'paramiko',
            'docker',
      ],
      scripts=[
            'bin/yog',
      ])
