# Note: It is important to make sure you include the <bsd.kmod.mk> makefile after declaring the KMOD and SRCS variables.

CFLAGS += -g 
# Declare Name of kernel module
KMOD =   ng_route
# Enumerate Source files for kernel module
SRCS =   ng_route.c  ng_route.h

# Include kernel module makefile
# /usr/src/share/mk/bsd.kmod.mk
.include <bsd.kmod.mk>

# Not really necessary, 'make clean' will work fine
realclean: clean
	rm -f @ machine *~ *core
