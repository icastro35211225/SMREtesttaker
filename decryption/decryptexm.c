#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sha2.h>
#include <sys/types.h>

char exmHeader[1024] = "";
char exmContent[6000] = "";
unsigned char first64[64];
unsigned char exmBytes[6000];
unsigned char keyField[65537];
unsigned char decryptedHash[32];

void printUint(unsigned int something);

void printF64(){
	int i;
	for(i = 0; i < 64; i++){
		printf("%02X", first64[i]);
	}
	printf("\n");
}

void readKeyData(){
	FILE *keyFile = fopen("./keyData", "r");
	int i;
	for(i = 0; i <= 65536; i++){
		fscanf(keyFile, "%02x", &keyField[i]);
    }
	fclose(keyFile);
}

void readExmData(){
	FILE *exmFile = fopen("./decryptme.exm", "r");
	char tmp[5] = "";
	fgets(exmHeader, sizeof(exmHeader), exmFile);
	fgets(tmp, sizeof(tmp), exmFile);
	fgets(exmContent, sizeof(exmContent), exmFile);
	//printf("Header: %s\n\n", exmHeader);
	//printf("EXM Content: %s\n", exmContent);
	int i;
	for(i = 0; i < 64; i++){
		sscanf(&exmContent[i*2], "%02X", &first64[i]);
	}
	for(i = 64; i < 2531; i++){
		sscanf(&exmContent[i*2], "%02X", &exmBytes[i-64]);
	}
	printf("First 64 bytes: ");
	printF64();
	fclose(exmFile);
}

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

void decryptStage2(unsigned int *stageOneBytes, unsigned char *ciphertext, int ciphLen){
	unsigned int u1 = 0x10001;
	unsigned char* keyData = keyField;
	stageOneBytes = &stageOneBytes[2];
	int i, j;
	for(j = 0; j < 3; j++){
		for(i = 0; i < ciphLen; i++){
			ciphertext[i] = ciphertext[i] ^ (unsigned char) *(*stageOneBytes + keyData);
			unsigned int u3 = stageOneBytes[3] + *stageOneBytes;
			*stageOneBytes = u3;
			if(u1 <= u3){
				*stageOneBytes = u3 - u1;
			}
		}
		stageOneBytes--;
	}
}

unsigned int* decryptStage1(unsigned int *hash){
	unsigned int u1 = 0x10001;
	unsigned int *stage1Bytes = 0;

	stage1Bytes = malloc(sizeof(unsigned int) * 6);
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
	//puts("Stop here to check hash");
	return stage1Bytes;
}

int main(int argc, char *argv[]) {
	readKeyData();
	unsigned int hwHash[8] = {0xd40c6691, 0x15fed41b, 0x03ab5193, 0xe9a37c6b, 0x9f2a6098, 0x62b370ec, 0x17e011ca, 0xe306e77f};
	unsigned int *stage1Bytes = 0;
	readExmData();
	stage1Bytes = decryptStage1(hwHash);
	decryptStage2(stage1Bytes, first64, 64);
	printf("Printing decrypted bytes!: ");
	//312E303791660CD41BD4FE159351AB036B7CA3E998602A9FEC70B362CA11E0177FE706E3323032312F31322F31353A3A31313A35393A30302B0000F027ED99F8
	printF64();
	decryptStage2(stage1Bytes, exmBytes, 2531);
	printf("Decrypted? Exm content: %s\n", exmBytes);
	free(stage1Bytes);
	return 0;
}
