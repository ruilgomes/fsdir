from setuptools import setup, Extension
setup(
    name="fsdir",
    version="1.0.0",
    ext_modules=[
        Extension(
            "fsdir",
            sources=["fsdir.c"],
            libraries=["z"],
            extra_compile_args=["-O3", "-std=c11", "-pthread"],
        )
    ],
)
