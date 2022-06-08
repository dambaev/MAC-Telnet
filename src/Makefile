bin_PROGRAMS = mactelnet macping mndp
sbin_PROGRAMS = mactelnetd

mactelnet_SOURCES = config.h mactelnet.c mactelnet.h interfaces.c interfaces.h protocol.c protocol.h console.c console.h md5.c md5.h mndp.c mndp.h autologin.c autologin.h extra.h utlist.h
mactelnet_CFLAGS = -DHAVE_CONFIG_H -D__USE_MISC=1 -DFROM_MACTELNET -I. -DLOCALEDIR='"/usr/local/share/locale/"'

mactelnetd_SOURCES = config.h mactelnetd.c protocol.c protocol.h interfaces.c interfaces.h console.c console.h users.c users.h md5.c md5.h extra.h utlist.h
mactelnetd_CFLAGS = -DUSERSFILE='"$(sysconfdir)/mactelnetd.users"'

mndp_SOURCES = config.h mndp.c mndp.h protocol.c protocol.h extra.h

macping_SOURCES = config.h macping.c interfaces.c interfaces.h protocol.c protocol.h extra.h utlist.h
macping_CFLAGS = -DHAVE_CONFIG_H -D__USE_MISC=1 -I. -DLOCALEDIR='"/usr/local/share/locale/"'

AM_CPPFLAGS = -DLOCALEDIR='"$(localedir)"'

%.o: %.c
	gcc $(CFLAGS) $(mactelnet_CFLAGS) $(macping_CFLAGS) -c -o $@ $<

mactelnet_OBJS= $(mactelnet_SOURCES:.c=.o)
macping_OBJS= $(macping_SOURCES:.c=.o)

.PHONY: all clean

mactelnet: $(mactelnet_OBJS)
	gcc $(CFLAGS) $(mactelnet_CFLAGS) -o $@ $(mactelnet_OBJS) $(LDFLAGS)

macping: $(macping_OBJS)
	gcc $(CFLAGS) $(macping_CFLAGS) -o $@ $(macping_OBJS) $(LDFLAGS)

all: macping mactelnet

install:
	mkdir -p /usr/local/bin
	cp macping mactelnet /usr/local/bin

clean:
	rm *.o macping mactelnet
