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

static char *help = "-f file_name -s seed -w<MMIO write> -r <MMIO read> -x <MMIO write and read> e.g. -f /dev/pcicdx/ksb_cdx_dev0 -s 0xdeadfeed -x";

int main(int argc, char **argv)
{
	int fd, c;
	unsigned long cmd = KSB_MMIO_WR_RD;
	char *file_name = "/dev/pcicdx/ksb_cdx_dev0";
	ksb_user_cmd_t usr_cmd = { .wr_data = 0xFEEDFEED };

	while ((c = getopt(argc, argv, "f:s:rwx")) != -1) {
		switch (c)
		{
			case 'f':
				file_name = optarg;
				break;
			case 'r':
				cmd = KSB_MMIO_RD;
				break;
			case 's':
				usr_cmd.wr_data = strtoul(optarg, NULL, 16);
				break;
			case 'w':
				cmd = KSB_MMIO_WR;
				break;
			case 'x':
				cmd = KSB_MMIO_WR_RD;
				break;
			case '?':
				printf("help:  %s.\n", help);
				return 1;
			default:
				abort ();
		}
	}

	printf("\nOpening Driver [%s]\n", file_name);

	fd = open("/dev/pcicdx/ksb_cdx_dev0", O_RDWR);
	if(fd < 0) {
		printf("Cannot open device file...\n");
		return 0;
	}

	switch (cmd) {
	case KSB_MMIO_WR:	printf("Executing MMIO write test\n");	break;
	case KSB_MMIO_RD:	printf("Executing MMIO read test\n");	break;
	case KSB_MMIO_WR_RD:	printf("Executing MMIO write & read test\n");	break;
	}

	ioctl(fd, cmd, &usr_cmd);
	if (usr_cmd.err_code)
		printf("MMIO test failed with err:%x\n", usr_cmd.err_code);
	else
		printf("MMIO test completed\n");

	if (cmd == KSB_MMIO_WR_RD) {
		if (usr_cmd.wr_data != usr_cmd.rd_data)
			printf("Data mismatched, read: %0lX expected: %0lX\n", usr_cmd.rd_data, usr_cmd.wr_data);
	}

	printf("Closing Driver\n");
	close(fd);

	return 0;
}
