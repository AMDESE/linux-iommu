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

#include "../include/ksb_user.h"

static char *help = "-f file_name -s dma_size -r<DPU read> -w<DPU Write> -x<DPU Read and Write> -d dpu_exerciser_instance\n" \
					"e.g. dpu-test -f /dev/pcicdx/ksb_cdx_dev1 -s 256 -x";

int main(int argc, char **argv)
{
	int fd, c, i;
	char *src, *dst;
	unsigned long cmd = KSB_DMA_RD_WR_USER;
	char *file_name = "/dev/pcicdx/ksb_cdx_dev0";
	ksb_user_cmd_t usr_cmd = { .req_size = 256, .dpu_exe_instance = -1, .addr_mapped = 0};

	while ((c = getopt(argc, argv, "d:f:s:rwx")) != -1) {
		switch (c)
		{
			case 'd':
				usr_cmd.dpu_exe_instance = atoi(optarg);
				break;
			case 'f':
				file_name = optarg;
				break;
			case 'r':
				cmd = KSB_DMA_RD_USER;
				break;
			case 's':
				usr_cmd.req_size = atoi(optarg);
				break;
			case 'w':
				cmd = KSB_DMA_WR_USER;
				break;
			case 'x':
				cmd = KSB_DMA_RD_WR_USER;
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

	usr_cmd.src = malloc(usr_cmd.req_size);
	if (!usr_cmd.src)
		goto src_malloc_fail;

	if (cmd == KSB_DMA_RD_WR_USER) {
		usr_cmd.dst = malloc(usr_cmd.req_size);
		if (!usr_cmd.dst)
			goto dst_malloc_fail;
	}

	src = (char *)usr_cmd.src;
	dst = (char *)usr_cmd.dst;

	for (i = 0; i < usr_cmd.req_size; ++i)
		src[i] = i;

	switch (cmd) {
	case KSB_DMA_RD_WR_USER:
		printf("Executing DMA Read and write commands\n");
		break;
	case KSB_DMA_RD_USER:
		printf("Executing DMA Read command\n");
		break;
	case KSB_DMA_WR_USER:
		printf("Executing DMA write command\n");
		break;
	}

	ioctl(fd, cmd, &usr_cmd);
	if (usr_cmd.err_code)
		printf("DPU command failed with err:%x\n", usr_cmd.err_code);
	else {
		printf("DPU command completed\n");
	}

	if (cmd == KSB_DMA_RD_WR_USER) {
		for (i = 0; i < usr_cmd.req_size; ++i) {
			if (src[i] != dst[i]) {
				printf("Data mismatched at : %d\n", i);
				break;
			}
		}
	}

	printf("Closing Driver\n");
	if (usr_cmd.dst)
		free(usr_cmd.dst);
dst_malloc_fail:
	if (usr_cmd.src)
		free(usr_cmd.src);
src_malloc_fail:
	close(fd);

	return 0;
}
