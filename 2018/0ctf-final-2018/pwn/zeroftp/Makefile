CC = gcc
CFLAG = -g -D_FORTIFY_SOURCE=2 -w -D ZEROFS -D SHELL -D PWN
LDFLAG = -z now
PROG = zeroftp zero_pack md5 zero_utils crc32 zerofs
EXEC = zeroftp

debug: $(EXEC)

zeroftp: $(PROG:=.o)
	$(CC) $(LDFLAG) $^ -o $(EXEC)

%.o: %.c
	$(CC) $(CFLAG) -g -c $< -o $@

clean:
	rm -f $(EXEC) $(PROG:=.o)
