TOOL	= oscetool
OBJS	= aes.o aes_omac.o backend.o bn.o ec.o ids.o keys.o list.o \
	  main.o mt19937.o npdrm.o rvk.o self.o sha1.o spp.o util.o \
	  patches.o klics.o

#CC	= gcc
CFLAGS	= -g -O2 -Wall -W
LDFLAGS = -lz #-static

all: $(TOOL)

aes.o: aes.c polarssl/aes.h
aes_omac.o: aes_omac.c types.h polarssl/aes.h
backend.o: backend.c backend.h types.h list.h self.h keys.h util.h rvk.h \
		 spp.h npdrm.h ids.h
bn.o: bn.c types.h
ec.o: ec.c types.h bn.h keys.h util.h mt19937.h
ids.o: ids.c util.h types.h ids.h
keys.o: keys.c keys.h types.h util.h self.h list.h ids.h backend.h \
 		npdrm.h polarssl/aes.h
main.o: main.c backend.h types.h list.h self.h keys.h util.h
mt19937.o: mt19937.c types.h mt19937.h
npdrm.o: npdrm.c npdrm.h types.h backend.h list.h self.h keys.h util.h \
 		polarssl/aes.h polarssl/sha1.h ec.h aes_omac.h ids.h
rvk.o: rvk.c rvk.h self.h list.h types.h keys.h util.h ids.h
self.o: self.c self.h list.h types.h keys.h util.h backend.h npdrm.h \
 		ids.h mt19937.h polarssl/sha1.h polarssl/aes.h ec.h
sha1.o: sha1.c polarssl/sha1.h
spp.o: spp.c spp.h self.h list.h types.h keys.h util.h
util.o: util.c util.h types.h polarssl/sha1.h

$(TOOL): %:  $(OBJS) 
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(OBJS): %.o: %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -f $(OBJS) $(TOOL)

