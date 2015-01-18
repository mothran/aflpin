#include <stdio.h>
#include <unistd.h>

void printer() {
	printf("hello\n");
	sleep(5);
}

int main(int argc, char **argv) {
	printf("hello this is the start\n");

	if (argc < 5) {
		printer();
	}
}