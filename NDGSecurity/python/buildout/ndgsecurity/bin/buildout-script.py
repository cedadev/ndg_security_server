#!"C:\Python25\python.exe"

import sys
sys.path[0:0] = [
  'c:\\documents and settings\\philip\\workspace\\python\\buildout\\ndgsecurity\\eggs\\setuptools-0.6c9-py2.5.egg',
  'c:\\documents and settings\\philip\\workspace\\python\\buildout\\ndgsecurity\\eggs\\zc.buildout-1.2.1-py2.5.egg',
  ]

import zc.buildout.buildout

if __name__ == '__main__':
    zc.buildout.buildout.main()
