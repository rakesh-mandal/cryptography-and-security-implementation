CC     ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra
SRC    = params.c crypto.c general.c ntt.c kpke.c mlkem.c

.PHONY: test demo bench bench_time clean

test: $(SRC) test.c
	$(CC) $(CFLAGS) $(SRC) test.c -o /tmp/mlkem_test
	/tmp/mlkem_test

demo: $(SRC) demo.c
	$(CC) $(CFLAGS) $(SRC) demo.c -o demo
	./demo

bench: $(SRC) bench.c
	$(CC) -O3 -march=native -std=c11 -Wall -Wextra $(SRC) bench.c -o /tmp/mlkem_bench
	/tmp/mlkem_bench

bench_time: $(SRC) bench_time.c
	$(CC) -O3 -march=native -std=c11 -Wall -Wextra $(SRC) bench_time.c -o /tmp/mlkem_bench_time
	/tmp/mlkem_bench_time

clean:
	rm -f demo /tmp/mlkem_test /tmp/mlkem_bench /tmp/mlkem_bench_time
