# directories visited install, programs, check, etc.
SUBDIRS=source/common source/protocol source/gather 
-include ./Makefile.inc
all: src

src:
	@for d in $(SUBDIRS); do (cd $$d && $(MAKE)); done
	
format:
	@for d in $(SUBDIRS); do (cd $$d && $(MAKE) format); done

install: 
	mkdir -p $(PREFIX)
	mkdir -p $(PREFIX)/bin
	mkdir -p $(PREFIX)/etc
	mkdir -p $(PREFIX)/tmp
	mkdir -p $(PREFIX)/log
	@for d in $(SUBDIRS); do (cd $$d && $(MAKE) install); done

uninstall:
	@for d in $(SUBDIRS); do (cd $$d && $(MAKE) uninstall); done

clean:
	@for d in $(SUBDIRS); do (cd $$d && $(MAKE) clean); done