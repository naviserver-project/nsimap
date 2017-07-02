ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

# Location of the UW IMAP c-client library source for RH7.3 and up
IMAPFLAGS  = -I/usr/include/imap $(SSL)
# RedHat 8.x
#IMAPLIBS   = /usr/lib/c-client.a -L/usr/kerberos/lib -lgssapi_krb5 -lpam
# Mandrake 10.x, Debian Sarge
#IMAPLIBS   = /usr/lib/libc-client.a -L/usr/kerberos/lib -lgssapi_krb5 -lpam
# Arch Linux 0.7
IMAPLIBS   = /usr/lib/libc-client.a -lpam -lcrypt

#
# Module name
#
MOD      =  nsimap.so

#
# Objects to build.
#
MODOBJS  = nsimap.o
CFLAGS	 = $(IMAPFLAGS) -g
MODLIBS	 = $(IMAPLIBS) $(SSLLIBS)

include  $(NAVISERVER)/include/Makefile.module

