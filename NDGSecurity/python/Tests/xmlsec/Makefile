PROGRAM = verify3
PROGRAM_FILES = $(PROGRAM).c
VALGRIND_FLAGS=-O0 -O1

#PKG_CONFIG_PATH=/usr/local/lib/pkgconfig/

CFLAGS	+= -g $(VALGRIND_FLAGS) \
$(shell pkg-config --cflags xmlsec1)
LIBS   += $(shell pkg-config --libs xmlsec1)

#CFLAGS	+= -g $(VALGRIND_FLAGS) \
#$(shell pkg-config \
#--define-variable=prefix=/usr/local \
#--define-variable=libdir=/usr/local/lib --cflags xmlsec1)
#LDFLAGS	+= #-L/usr/local/lib 
#LIBS 	+= $(shell pkg-config \
#--define-variable=prefix=/usr/local \
#--define-variable=libdir=/usr/local/lib --libs xmlsec1)

all: $(PROGRAM)

%: %.c 
	$(CC) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(LIBS)

clean:
	@rm -rf $(PROGRAM)
