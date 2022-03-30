#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sha2.h>
#include <sys/types.h>

char exmHeader[1024] = "";
char exmContent[50000] = "";
unsigned char first64[64];
unsigned char exmBytes[50000];
unsigned char keyField[65537];
unsigned char decryptedHash[32];
int lenContent = 0;

typedef uint8_t HASH;

void printUint(unsigned int something);

int compareHash(HASH *userHash){
	if(memcmp(&first64[4], userHash, 32) == 0){
		return 1;
	}
	return 0;
}

void genHash(HASH *hash, char *data){
  // "abc" = 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  SHA2_CTX ctx;
  int lenData;
  HASH results[SHA256_DIGEST_LENGTH];
  lenData = strlen(data);
  SHA256Init(&ctx);
  SHA256Update(&ctx, (HASH*)data, lenData);
  SHA256Final(results, &ctx);
  //copy results to hash
  memcpy(hash, results, SHA256_DIGEST_LENGTH);
}

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

void readExmData(char *path){
	FILE *exmFile = fopen(path, "r");
	if(exmFile == NULL){
		fprintf(stderr, "Failed to open exm file %s, exiting\n", path);
		exit(1);
	}
	char tmp[5] = "";
	fgets(exmHeader, sizeof(exmHeader), exmFile);
	fgets(tmp, sizeof(tmp), exmFile);
	fgets(exmContent, sizeof(exmContent), exmFile);
	lenContent = (strlen(exmContent)-128)/2;
	//printf("Header: %s\n\n", exmHeader);
	//printf("EXM Content: %s\n", exmContent);
	int i;
	for(i = 0; i < 64; i++){
		sscanf(&exmContent[i*2], "%02X", &first64[i]);
	}
	for(i = 64; i < lenContent; i++){
		sscanf(&exmContent[i*2], "%02X", &exmBytes[i-64]);
	}
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

unsigned int* decryptStage1(HASH* hashP){
	unsigned int u1 = 0x10001;
	unsigned int *stage1Bytes = 0;
	unsigned int *hash = (unsigned int *) hashP;

	stage1Bytes = malloc(sizeof(unsigned int) * 6);
	//Print the hash
	//printf("'hw' sha256 Hash: ");
	//for(int i = 0; i < 8; i++){
		//printOp(hash[i]);
	//}
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

void printHash(HASH *hash){
  printf("0x");
  for(int i = 0 ; i < SHA256_DIGEST_LENGTH; i++){
    printf("%02x", hash[i]);
  }
  printf("\n");
}

int main(int argc, char *argv[]) {
	if(argc != 3){
		printf("Usage: %s <exm path> <password>", argv[0]);
		exit(1);
	}
	readKeyData();
	HASH *userHash = NULL;
	userHash = (HASH *) malloc(sizeof(HASH)*SHA256_DIGEST_LENGTH);
	genHash(userHash, argv[2]);
	printf("Hash of \"%s\": ", argv[2]);
	printHash(userHash);
	//unsigned int hwHash[8] = {0xd40c6691, 0x15fed41b, 0x03ab5193, 0xe9a37c6b, 0x9f2a6098, 0x62b370ec, 0x17e011ca, 0xe306e77f};
	//unsigned int hwHash[8] = {0xdbe75582, 0xcc63df40, 0xf19aef63, 0x91d76ce5, 0x35f64f2f, 0x017dc86b, 0x287b4f8b, 0x4df94137};
	                        //0x8255e7db, 0x40df63cc, 0x63ef9af1, 0xe56cd791, 0x2f4ff635, 0x6bc87d01, 0x8b4f7b28, 0x3741f94d
	unsigned int *stage1Bytes = 0;
	readExmData(argv[1]);
	stage1Bytes = decryptStage1(userHash);
	decryptStage2(stage1Bytes, first64, 64);
	if(compareHash(userHash) == 0){
		printf("\nFailed to decrypt - wrong password\n");
		free(stage1Bytes);
		free(userHash);
		exit(1);
	}
	decryptStage2(stage1Bytes, exmBytes, lenContent);
	printf("\nDecrypted EXM Content:\n\n%s%s\n", exmHeader, exmBytes);
	free(stage1Bytes);
	free(userHash);
	return 0;
}
