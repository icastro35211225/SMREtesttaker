#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char exmHeader[1024] = "";
char exmContent[80000] = "";
unsigned char first64[65];
unsigned char exmBytes[80000];
unsigned char keyField[65537];
unsigned char decryptedHash[32];
unsigned int lenContent = 0;

/*********************************************************************
* SHA256 Functions Author:     Brad Conte (brad AT bradconte.com)
* Sourced From: https://github.com/B-Con/crypto-algorithms/
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <memory.h>
#include "sha256.h"

/****************************** MACROS ******************************/
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/
void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}
void printUint(unsigned int something);

int compareHash(BYTE *userHash){
	if(memcmp(&first64[4], userHash, 32) == 0){
		return 1;
	}
	return 0;
}

void genHash(BYTE *hash, char *data){
  // "abc" = 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  SHA256_CTX ctx;
  int lenData;
  BYTE results[SHA256_BLOCK_SIZE];
  lenData = strlen(data);
  sha256_init(&ctx);
  sha256_update(&ctx, (BYTE*)data, lenData);
  sha256_final(&ctx, results);
  //copy results to hash
  memcpy(hash, results, SHA256_BLOCK_SIZE);
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
	lenContent = (((strlen(exmContent))/2));
	//printf("Header: %s\n\n", exmHeader);
	printf("LENGTH: %d\nEXM Content: %s\n", lenContent, exmContent);
	unsigned int i;
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

unsigned int* decryptStage1(BYTE* hashP){
	unsigned int u1 = 0x10001; //len of key file
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
	return stage1Bytes;
}

void printHash(BYTE *hash){
  printf("0x");
  for(int i = 0 ; i < SHA256_BLOCK_SIZE; i++){
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
	BYTE *userHash = NULL;
	userHash = (BYTE *) malloc(sizeof(BYTE)*SHA256_BLOCK_SIZE);
	genHash(userHash, argv[2]);
	printf("Hash of \"%s\": ", argv[2]);
	printHash(userHash);
	unsigned int *stage1Bytes = 0;
	readExmData(argv[1]);
	stage1Bytes = decryptStage1(userHash);
	decryptStage2(stage1Bytes, first64, 64);
	printf("First 64 Bytes: ");
	printF64();
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
