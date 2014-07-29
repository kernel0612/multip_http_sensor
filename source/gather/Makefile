-include ../../Makefile.inc
INCLUDEPATH=-I.. -I$(PCAP_include) -I../.. -I../common -I../protocol -I$(ACE_include) \
-I$(PCAP_include) -I$(BOOST_include) -I$(LIBXML2_include) \
-I$(PGSQL_include) -I$(berkeleyDB_include)
LIBPATH=-L../common -L../protocol -L$(ACE_lib)  \
-L$(BOOST_lib) -L$(PCAP_lib) -L$(PGSQL_lib) -L$(LIBXML2_lib) -L$(berkeleyDB_lib)

LIBS=-lstdc++ -lcommons -lnetwork -lprotobuf -lpcap -lACE -lxml2  -lpgtypes -lpq -ldb ../common/libssdb.a ../common/libtinyxml.a
CPPFLAGS=-ggdb -static -fomit-frame-pointer -pipe -Wall -Wno-deprecated -DDEBUG

SRCS= $(wildcard *.cpp)
OBJS= $(patsubst %.cpp, %.o, $(SRCS))
PROJECT=gather

all: depend $(PROJECT)

depend:	$(SRCS)
	$(CXX) -MM $(INCLUDEPATH) $(ALLFLAGS) $(SRCS) > depend
-include depend

$(PROJECT):	$(OBJS)
	$(CXX) $(LIBPATH) -o $@ $(OBJS) $(LIBS) 

clean:
	rm -f depend
	rm -f $(OBJS) $(PROJECT)
	

%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(INCLUDEPATH) -o $@ $< -c

format:
	astyle -A8 -s2 -a -m -f -Y -xd -j -k3 -W3 -z2 -U -H -p -n *.cpp *.h

install:
	cp -rf $(PROJECT) $(PREFIX)/bin/.
	
uninstall:
	rm -rf $(PREFIX)/bin/$(PROJECT)
	
