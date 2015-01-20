#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>


void vulnerable(char *mem)
{
	char buff[20];
	strncpy(buff, mem, (unsigned int) mem[0]);
	printf("size: %d\n", (unsigned int) mem[0]);
	printf("%s\n", buff);
}

int main(int argc, char **argv)
{
	int fd;
	struct stat st;

	char buffer[2000];

	if (argc < 2) {
		printf("Please provide a file\n");
		exit(0);
	}

	if ((fd = open(argv[1], O_RDONLY)) < 0) {
		printf("error reading file");
		exit(-1);
	}

	if (fstat (fd, &st) < 0) {
		printf("stating file");
		exit(-1);
	}

	// bad size here, could lead to a secondary issue. 
	read(fd, buffer, st.st_size);

	vulnerable(buffer);

	return 0;
}