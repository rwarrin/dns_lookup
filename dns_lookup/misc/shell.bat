@ECHO off

SET RootDir=%cd:~0,-15%

SUBST Y: /D
SUBST Y: %RootDir%

PUSHD Y:

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
start gvim

