@ECHO OFF
REM Command file for Sphinx documentation (Windows)
if "%SPHINXBUILD%" == "" set SPHINXBUILD=sphinx-build
set SOURCEDIR=.
set BUILDDIR=_build
%SPHINXBUILD% -M %1 %SOURCEDIR% %BUILDDIR% -W --keep-going %SPHINXOPTS% %O%
