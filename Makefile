CC = gcc

CFLAGS = -Wall -Werror
# CFLAGS += -g

STATIC = -L../libgcrypt-1.7.6/src/.libs -lgcrypt \
					-L../libgpg-error-1.27/src/.libs -lgpg-error

LDFLAGS = $(shell libgcrypt-config --libs)

src = vukextract.c
obj = $(src:.c=.o)

all: vukextract

#normal shared linking
vukextract: $(obj)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

#static linking for prebuild binaries
static: $(obj)
	$(CC) $(CFLAGS) -o $@ $^ -static $(STATIC)

clean:
	rm -f $(obj) vukextract
