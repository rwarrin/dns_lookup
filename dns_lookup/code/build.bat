@echo off

SET CompilerFlags=-nologo -Zi -Od -Oi -FC -Gs- -fsanitize=address -fp:fast
REM SET CompilerFlags=-nologo -O2 -Oi -fp:fast -FC -Gs-
SET LinkerFlags=-incremental:no -opt:ref

IF NOT EXIST build mkdir build
pushd build

cl.exe %CompilerFlags% ..\dns_lookup\code\dns_lookup.cpp /link %LinkerFlags%

popd
