#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <sys/mman.h>

#include "../include/ksb_user.h"

#define MIN_PKT_COUNT 500000000
#define MAX_TEST_DURATION_MS	(1000 * 60 * 15)
#define US_PER_S 1000000
#define US_PER_MS 1000
#define MS_PER_S 1000
#define NS_PER_MS 1000000ULL
#define NS_PER_US 1000
#define NS_PER_S (MS_PER_S * NS_PER_MS)

#define BITS_PER_KILOBIT     1000
#define KILOBITS_PER_MEGABIT 1000
#define BITS_PER_MEGABIT     (BITS_PER_KILOBIT * KILOBITS_PER_MEGABIT)
#define BITS_PER_BYTE        8

#define HUGE_PAGE_SIZE (2 * 1024 * 1024) /* 2 MB huge page size */

static char *help = "-f file_name -s dma_size -r<DMA Read> [f-Fabric | b-Buffer] -w<DMA Write> -d dpu_exerciser_instance -p packet_count\n" \
					"e.g. dpu-test -f /dev/pcicdx/ksb_cdx_dev1 -s 8192 -r b -t 3000\n";

int main(int argc, char **argv)
{
	int fd, c, i;
	char *src, *dst;
	uint64_t rate, bytes, bandwidth;
	unsigned long cmd = KSB_DMA_PERF_WR_USER;
	char *file_name = "/dev/pcicdx/ksb_cdx_dev0";
	ksb_user_cmd_t usr_cmd = { .req_size = 256, .dpu_exe_instance = -1, usr_cmd.in_pkts = MIN_PKT_COUNT, .addr_mapped = 0, .dma_rd_fabric = 1 };

	while ((c = getopt(argc, argv, "d:f:s:p:r:w")) != -1) {
		switch (c)
		{
			case 'd':
				usr_cmd.dpu_exe_instance = atoi(optarg);
				break;
			case 'f':
				file_name = optarg;
				break;
			case 'r':
				if (optarg[0] == 'f' || optarg[0] == 'F') {
					usr_cmd.dma_rd_fabric = 1;
				} else if (optarg[0] == 'b' || optarg[0] == 'B') {
					usr_cmd.dma_rd_fabric = 0;
				} else {
					printf("Invalid option for DMA Read. Please provide valid option (f = DMA read to fabric, b = DMA read to DPU buffer)\n");
					printf("help:  %s.\n", help);
					return 1;
				}
				cmd = KSB_DMA_PERF_RD_USER;
				break;
			case 's':
				usr_cmd.req_size = atoi(optarg);
				break;
			case 'p':
				usr_cmd.in_pkts = strtoul(optarg, NULL, 10);
				if (usr_cmd.in_pkts < MIN_PKT_COUNT)
					printf("Low sample size. Results may vary. Please run for min %0d packets\n", MIN_PKT_COUNT);
				break;
			case 'w':
				cmd = KSB_DMA_PERF_WR_USER;
				break;
			case '?':
				printf("help:  %s.\n", help);
				return 1;
			default:
				abort ();
		}
	}

	printf("\nOpening Driver [%s]\n", file_name);

	fd = open(file_name, O_RDWR);
	if(fd < 0) {
		printf("Cannot open device file...\n");
		return 0;
	}

	usr_cmd.src = mmap(NULL, HUGE_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	if (usr_cmd.src == MAP_FAILED) {
		perror("Failed to allocate huge pages in user space");
		goto src_malloc_fail;
	}

	src = (char *)usr_cmd.src;

	for (i = 0; i < usr_cmd.req_size; ++i)
		src[i] = i;

	switch (cmd) {
	case KSB_DMA_PERF_RD_USER:
		printf("Executing DMA read performance test for %0lu pkts\n", usr_cmd.in_pkts);
		break;
	case KSB_DMA_PERF_WR_USER:
		printf("Executing DMA write performance test for %0lu pkts\n", usr_cmd.in_pkts);
		break;
	}

	ioctl(fd, cmd, &usr_cmd);
	if (usr_cmd.err_code) {
		printf("DPU command failed with err:%x\n", usr_cmd.err_code);
	}
	else {
		rate = (usr_cmd.out_loops * NS_PER_S) / usr_cmd.out_duration_ns;
		bytes = usr_cmd.out_loops * usr_cmd.req_size;
		bandwidth = (bytes * BITS_PER_BYTE * (NS_PER_S / BITS_PER_MEGABIT)) / usr_cmd.out_duration_ns;

		printf("Statistics\n");
		printf("%20s: %-11" PRIu64 " io/s\n", "Packet rate", rate);
		printf("%20s: %-11" PRIu64 " Mbit/s\n", "Bandwidth", bandwidth);
		printf("%20s: %-11llu ms\n", "Test duration", usr_cmd.out_duration_ns / NS_PER_MS);

		printf("\n");
	}

	printf("Closing Driver\n");
	if (usr_cmd.src != MAP_FAILED)
		munmap(usr_cmd.src, HUGE_PAGE_SIZE);
src_malloc_fail:
	close(fd);

	return 0;
}
