TARGET = cdx-test dpu-test dpu-perf mmio-test dpu-perf-stats

all: cdm-test dpu-test dpu-perf mmio-test dpu-perf-stats

cdm-test: cdx_test.o
	$(CC) -o cdx-test cdx_test.o

dpu-test: dpu_test.o
	$(CC) -o dpu-test dpu_test.o

dpu-perf: dpu_perf.o
	$(CC) -o dpu-perf dpu_perf.o

dpu-perf-perf: dpu_perf_stats.o
	$(CC) -o dpu-perf-stats dpu_perf_stats.o

mmio-test: mmio_test.o
	$(CC) -o mmio-test mmio_test.o

.PHONY: clean
clean:
	rm -f *.o ${TARGET}

