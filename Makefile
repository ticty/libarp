####################################################
# Makefile for 'libarp'
# bug please report to dev.guofeng@gmail.com
####################################################

TARGET = libarp.a
TARGETLIB = $(TARGET)


## target descript
OBJ_DIR = .obj

SRCS = arp.c \
		eth.c \
		interface.c \
       network.c \
       misc.c

HEADS = arp.h \
        eth.h \
        interface.h \
        network.h \
        misc.h \
        list.h

OBJS = ${SRCS:%.c=$(OBJ_DIR)/%.o}
DEPS = ${OBJS:.o=.d}


## build flag
CC = gcc
AR = ar crs
RM = rm -rf
MAKE = make
STRIP = strip
INSTALL = install

LIB_INSTALL_PREFIX = /usr/local/lib
HEAD_INSTALL_PREFIX = /usr/local/include/arp

CFLAGS  = -O2 -Wall -W\
          -MMD -MP -MF "$(@:%.o=%.d)" -MT "$@" -MT "$(@:%.o=%.d)"
LDFLAGS = -shared

ifneq ($(suffix $(TARGET)),.a)
CFLAGS += -fPIC
endif

## make some as globle variables
export CC RM STRIP TARGETLIB OBJ_DIR



## target rules
first: $(TARGET)

all: $(TARGET) test


-include $(DEPS)


$(TARGET): $(OBJS)
	@if [ "`basename $(TARGET) .a`" = "$(TARGET)" ]; \
	then \
		$(CC) $(LDFLAGS) -o "$@" $(OBJS); \
		echo "$(CC) $(LDFLAGS) -o $@ $(OBJS)"; \
	else \
		$(AR) "$@" $(OBJS); \
		echo "$(AR) $@ $(OBJS)"; \
	fi


$(OBJ_DIR)/%.o: %.c
	@test -d $(OBJ_DIR) || mkdir -p -m 777 $(OBJ_DIR)
	$(CC) $(CFLAGS) -c "$<" -o "$@"


test:
	$(MAKE) -C "$@"


strip:
	$(STRIP) $(TARGET)
	@$(MAKE) "$@" -C test


install:
	$(INSTALL) -d $(LIB_INSTALL_PREFIX)
	$(INSTALL) -m 0774 $(TARGET) $(LIB_INSTALL_PREFIX)
	$(INSTALL) -d $(HEAD_INSTALL_PREFIX)
	$(INSTALL) -m 0774 $(HEADS) $(HEAD_INSTALL_PREFIX)


uninstall:
	$(RM) $(LIB_INSTALL_PREFIX)/$(TARGET)
	$(RM) $(HEAD_INSTALL_PREFIX)


clean:
	$(RM) $(OBJS)
	@$(MAKE) "$@" -C test


distclean:
	$(RM) $(DEPS) $(OBJS) $(OBJ_DIR) $(TARGET)
	@$(MAKE) "$@" -C test


.PHONY: strip install uninstall clean distclean test


# End of Makefile
