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

int main()
{
	int fd;
	int32_t number = 0;
	ksb_user_cmd_t usr_cmd;

	printf("\nOpening Driver\n");

	fd = open("/dev/pcicdx/ksb_cdx_dev0", O_RDWR);
	if(fd < 0) {
		printf("Cannot open device file...\n");
		return 0;
	}

	usr_cmd.seed = 1;
	usr_cmd.req_size = 128;
	usr_cmd.req_count = 16;
	usr_cmd.err_code = 0;
	ioctl(fd, KSB_CDM_MSGST, &usr_cmd);

	if (usr_cmd.err_code)
		printf("MSG Store failed with err:%x\n", usr_cmd.err_code);
	else
		printf("Message store passed successfully\n");

	ioctl(fd, KSB_CDM_MSGLD, &usr_cmd);

	if (usr_cmd.err_code)
		printf("MSG Store failed with err:%x\n", usr_cmd.err_code);
	else
		printf("Message load passed successfully\n");

	printf("Closing Driver\n");
	close(fd);

	return 0;
}
