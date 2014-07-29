-include ../../Makefile.inc

INCLUDEPATH=-I/usr/include -I../.. -I.. -I$(ACE_include) -I$(LIBXML2_include) -I../protocol
LIBPATH=-L.
LINKLIB=-lstdc++
CPPFLAGS=-ggdb -static -fomit-frame-pointer -pipe -Wall -Wno-deprecated -DDEBUG

SRCS= $(wildcard *.cpp)
OBJS= $(patsubst %.cpp, %.o, $(SRCS))
PROJECT=libcommons.a
all: depend $(PROJECT)

depend: $(SRCS)
	$(CXX) -MM $(INCLUDEPATH) $(ALLFLAGS) $(SRCS) > depend
-include depend

$(PROJECT):	$(OBJS)
	$(AR) $@ $(OBJS)
	$(RANLIB) $@

format:
	astyle -A8 -s2 -a -m -f -Y -xd -j -k3 -W3 -z2 -U -H -p -n *.cpp *.h

clean:
	rm -f depend
	rm -f $(OBJS) $(PROJECT)
	
%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(INCLUDEPATH) -o $@ $< -c

install:
	echo instll
	
uninstall:
	echo uninstll
