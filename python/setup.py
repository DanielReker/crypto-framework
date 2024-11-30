# setup.py для ручного билда
# В build.bat команды для него

from setuptools import setup, Extension

example_module = Extension(
    '_cryptofw',
    sources=[
        'cryptofw_wrap.cxx',
        '../src/utils.cpp',
        '../src/CryptoProCertificate.cpp',
        '../src/CryptoProCsp.cpp',
        '../src/VipNetCertificate.cpp',
        '../src/VipNetCsp.cpp',
    ],
    include_dirs=[
        'D:/cpp projects/ustu labs/crypto-framework/include',
        'C:/Program Files (x86)/Crypto Pro/SDK/include',
    ],
    libraries=[
        'crypt32',
        'advapi32',
        'cades',
    ],
    library_dirs=[
        'C:/Program Files (x86)/Crypto Pro/SDK/lib/amd64',
    ],
)
setup (name = 'cryptofw',
       version = '0.1',
       author      = "SWIG Docs",
       description = """Simple swig example from docs""",
       ext_modules = [example_module],
       py_modules = ["cryptofw"],
       )