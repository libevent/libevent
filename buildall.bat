nmake -f Makefile.nmake clean

set BUILD_CFLAGS=/MT
nmake -f Makefile.nmake
mkdir lib\MT\Release
move libev*.lib lib\MT\Release
nmake -f Makefile.nmake clean

set BUILD_CFLAGS=/MTd
nmake -f Makefile.nmake
mkdir lib\MT\Debug
move libev*.lib lib\MT\Debug
nmake -f Makefile.nmake clean

set BUILD_CFLAGS=/MD
nmake -f Makefile.nmake
mkdir lib\MD\Release
move libev*.lib lib\MD\Release
nmake -f Makefile.nmake clean

set BUILD_CFLAGS=/MDd
nmake -f Makefile.nmake
mkdir lib\MD\Debug
move libev*.lib lib\MD\Debug
nmake -f Makefile.nmake clean

