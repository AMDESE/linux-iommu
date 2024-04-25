#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <unistd.h>

#include "../include/ksb_user.h"

static char *help = "-s <enable> e.g. dpu-test -s 1 or dpu-test -s 0\n";

int main(int argc, char **argv)
{
	unsigned long cmd = KSB_DMA_STATS_ENABLE;
	char *file_name = "/dev/pcicdx/ksb_cdx_dev0";
	ksb_stats_en_cmd_t stats_cmd;
	int fd, c, ret;

	while ((c = getopt(argc, argv, "s:")) != -1) {
		switch (c)
		{
			case 's':
				stats_cmd.enable = atoi(optarg);
				break;
			default:
				abort ();
		}
	}

	printf("Opening Driver [%s]\n", file_name);
	fd = open(file_name, O_RDWR);
	if(fd < 0) {
		printf("Cannot open device file...\n");
		return 0;
	}

	ret = ioctl(fd, KSB_DMA_STATS_ENABLE, &stats_cmd);
	if (ret)
		printf("Ioctl to enable/disable stats failed\n");

	printf("Closing Driver [%s]\n", file_name);
	close(fd);
	return 0;
}
