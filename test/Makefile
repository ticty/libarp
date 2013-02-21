####################################################
# Makefile for test examples of 'libarp'
# bug please report to dev.guofeng@gmail.com
####################################################

TARGET = send_ARP recv_ARP ARP_server


## target descript
CFLAGS  = -O2 -Wall -W\
          -MMD -MP -MF "$(@:%.o=%.d)" -MT "$@" -MT "$(@:%.o=%.d)"
INCLUDE = -I../../
LDFLAGS = -L../
LIBS = -larp
OBJS := 
DEPS := 

# send_ARP
send_ARP_SRCS = send_ARP.c
send_ARP_OBJS = ${send_ARP_SRCS:%.c=$(OBJ_DIR)/%.o}
send_ARP_DEPS = ${send_ARP_OBJS:.o=.d}
OBJS += $(send_ARP_OBJS)
DEPS += $(send_ARP_DEPS)

# recv_ARP
recv_ARP_SRCS = recv_ARP.c
recv_ARP_OBJS = ${recv_ARP_SRCS:%.c=$(OBJ_DIR)/%.o}
recv_ARP_DEPS = ${recv_ARP_OBJS:.o=.d}
OBJS += $(recv_ARP_OBJS)
DEPS += $(recv_ARP_DEPS)

# ARP_server
ARP_server_SRCS = ARP_server.c
ARP_server_OBJS = ${ARP_server_SRCS:%.c=$(OBJ_DIR)/%.o}
ARP_server_DEPS = ${ARP_server_OBJS:.o=.d}
OBJS += $(ARP_server_OBJS)
DEPS += $(ARP_server_DEPS)



## target rules
all: $(TARGET)


-include $(send_ARP_DEPS)


send_ARP: $(send_ARP_OBJS)
	$(CC) $(LDFLAGS) -o "$@" $(send_ARP_OBJS) $(LIBS)


recv_ARP: $(recv_ARP_OBJS)
	$(CC) $(LDFLAGS) -o "$@" $(recv_ARP_OBJS) $(LIBS)


ARP_server: $(ARP_server_OBJS)
	$(CC) $(LDFLAGS) -o "$@" $(ARP_server_OBJS) $(LIBS)


$(OBJ_DIR)/%.o: %.c
	@test -d $(OBJ_DIR) || mkdir -p -m 777 $(OBJ_DIR)
	$(CC) $(INCLUDE) $(CFLAGS) -c "$<" -o "$@"


strip:
	$(STRIP) $(TARGET)


clean:
	$(RM) $(OBJS) $(DEPS) $(OBJ_DIR)


distclean:
	$(RM) $(OBJS) $(DEPS) $(OBJ_DIR) $(TARGET)


.PHONY: strip clean distclean


# End of Makefile
