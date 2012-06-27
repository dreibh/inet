OSTYPE = $(shell uname)
ifeq ($(OSTYPE),Darwin)
HRTIMEFLAGS = -DHAVE_MACH_ABSOLUTE_TIME
endif
ifeq ($(OSTYPE),Linux)
HRTIMEFLAGS = -lrt -DHAVE_CLOCK_GETTIME
endif


all: checkmakefiles
	cd src && $(MAKE)

clean: checkmakefiles
	cd src && $(MAKE) clean

cleanall: checkmakefiles
	cd src && $(MAKE) MODE=release clean
	cd src && $(MAKE) MODE=debug clean
	rm -f src/Makefile

makefiles:
	# cd src && opp_makemake -f --deep -lpcap -lssl -lcrypto -DHAVE_PCAP -DUSE_TF -o inet -O out $$NSC_VERSION_DEF
	cd src && opp_makemake -f --deep -lpcap -lssl -lcrypto -DPRIVATE -DHAVE_PCAP -DUSE_TF -o inet -O out $$NSC_VERSION_DEF

checkmakefiles:
	@if [ ! -f src/Makefile ]; then \
	echo; \
	echo '======================================================================='; \
	echo 'src/Makefile does not exist. Please use "make makefiles" to generate it!'; \
	echo '======================================================================='; \
	echo; \
	exit 1; \
	fi

doxy:
	doxygen doxy.cfg

tcptut:
	cd doc/src/tcp && $(MAKE)
