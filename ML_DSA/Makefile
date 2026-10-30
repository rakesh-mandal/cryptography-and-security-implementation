CC      ?= gcc
CFLAGS  ?= -O3 -std=gnu99 -Wall -Wextra -Wpedantic
SRC      = mldsa.c fips202.c randombytes.c

test: test_mldsa
	./test_mldsa
test_mldsa: $(SRC) test_mldsa.c mldsa.h fips202.h mldsa_zetas.h
	$(CC) $(CFLAGS) $(SRC) test_mldsa.c -o $@
sanitize:
	$(CC) -O1 -g -fsanitize=address,undefined $(SRC) test_mldsa.c -o test_asan && ./test_asan
clean:
	rm -f test_mldsa test_asan bench *.o

bench: $(SRC) bench.c mldsa.h fips202.h mldsa_zetas.h
	$(CC) $(CFLAGS) $(SRC) bench.c -o $@ -lrt 2>/dev/null || $(CC) $(CFLAGS) $(SRC) bench.c -o $@
	./bench
