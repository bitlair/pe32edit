CC := gcc

# Enable for debug
CFLAGS := -g -ggdb -Wall -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Wdeclaration-after-statement -Werror-implicit-function-declaration -Werror -Wstrict-prototypes

INCLUDES := -I.

pe32edit_LIB := -ltalloc
pe32edit_OBJ := main.o lib/status.o lib/read_helper.o

OBJ := $(pe32edit_OBJ)

binaries := bin/pe32edit

all:	$(binaries)

clean:
	rm -f $(binaries)
	rm -f $(OBJ)
	rm -f $(OBJ:.o=.d)

%.o: %.c
	@echo Compiling $*.c
	@$(CC) -c $(CFLAGS) $(INCLUDES) -o $*.o $<
	@$(CC) -MM $(CFLAGS) -MT $*.o $(INCLUDES) -o $*.d $<

bin/pe32edit: $(pe32edit_OBJ)
	@echo Linking bin/pe32edit
	@$(CC) $(pe32edit_OBJ) $(pe32edit_LIB) -o bin/pe32edit

ctags:
	ctags `find -name \*.[ch]`

-include $(OBJ:.o=.d)
