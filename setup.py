from distutils.core import setup, Extension

bitdist = Extension('bitdist',
                    sources = ['bitdist.c'],
                    extra_compile_args=['-O2'])

setup(name = 'bitdist',
      version = '1.0',
      description = 'Effecient bitdistance computation',
      author = 'Pavel Odvody',
      license = 'MIT',
      author_email = 'podvody@redhat.com',
      ext_modules = [bitdist])
