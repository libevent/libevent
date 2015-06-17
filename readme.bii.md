# Libevent 2.1

[![Biicode block](https://webapi.biicode.com/v1/badges/lasote/lasote/libevent/master)](https://www.biicode.com/lasote/libevent)

Also in [github repository https://github.com/lasote/libevent](https://github.com/lasote/libevent)

### Build status

*Visual Studio 2012:* OK! Pending Travis ci integration

*Linux gcc:* OK! Pending Appveyor integration

Also working with: **Windows** with **MinGW** >=4.8, **OSx** with **Clang** > 6.0

### How to use it?

- [Get started with biicode](http://docs.biicode.com/c++/gettingstarted.html)

- Just prefix your includes to libevent with block path "lasote/libevent"


        #include "lasote/libevent/include/event2/bufferevent.h"


    Or edit **[includes]** section in your *biicode.conf* file to map includes to lasote/libevent block and set the requirement manually:

	    [requirements]
	        lasote/libevent: 2 # !!!Check and put the last version here!
	    [includes]
	        event2/*.h: lasote/libevent/include


- Download the required dependencies:

        bii find


- Build the project:

        bii cpp:build # to build the project



Take a look to the examples at: [examples/libevent block](http://www.biicode.com/examples/libevent)
