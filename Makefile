CC = gcc -static -Wall -Werror
#CC = gcc -g -static -Wall -Werror
#CC = gcc -Wall -Werror

LDFLAGS = -L../libgcrypt-1.7.6/src/.libs -lgcrypt \
					-L../libgpg-error-1.27/src/.libs -lgpg-error

src = vukextract.c 
obj = $(src:.c=.o)

all: vukextract 


vukextract: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)


clean:
	rm -f $(obj) vukextract
