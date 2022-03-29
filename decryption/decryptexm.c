#include <stdio.h>

void printUint(unsigned int something){
	int i;
	for(i = 0; i < 4; i++){
		printf("%02X ", ((unsigned char*) &something)[i]);
	}
}

void printOp(unsigned short something){
	int i;
	for(i = 0; i < 2; i++){
		printf("%02X ", ((unsigned char*) &something)[i]);
	}
	printf("\n");
}

unsigned int* decryptStage1(unsigned int *hash){
	unsigned int u1 = 0x10001;
	unsigned int stage1Bytes[6] = {0, 0, 0, 0, 0, 0};
	//Print the hash
	printf("'hw' sha256 Hash: ");
	for(int i = 0; i < 8; i++){
		printUint(hash[i]);
	}
	printf("\nStage One Bytes:\n" );
	stage1Bytes[0] = hash[0] % u1;
	stage1Bytes[1] = hash[2] % u1;
	stage1Bytes[2] = hash[4] % u1;
	stage1Bytes[3] = (hash[1] % (u1-1)) + 1;
	stage1Bytes[4] = (hash[3] % (u1-1)) + 1;
	stage1Bytes[5] = (hash[5] % (u1-1)) + 1;
	int i;
	for(i = 0; i < 6; i++){
		printUint(stage1Bytes[i]);
		printf("\n");
	}
	puts("Stop here to check hash");
	return 0;
}

int main(int argc, char *argv[]) {
	unsigned int hwHash[8] = {0xd40c6691, 0x15fed41b, 0x03ab5193, 0xe9a37c6b, 0x9f2a6098, 0x62b370ec, 0x17e011ca, 0xe306e77f};
	decryptStage1(hwHash);
    return 0;
}
