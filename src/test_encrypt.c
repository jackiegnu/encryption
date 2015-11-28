#include "encrypt.h"
#include "rijndael.h"

#include <stdio.h>
#include <string.h>
#include "sim_api.h"

#define KEYBITS 128
#define N_FRAMES (1024*4)

/*unsigned char **createMatrix(int M, int N);
*/

int main(int argc, char **argv) {
	const char *password = "EmbCompArch";
	//Modify this point to the correct path that contains the src and testdata e.g
	//nst char input[] = "../data/input_plaintext.txt";
	const char input[] = "input/input.png";
	const char output[] = "cipherfile.txt";
	const char output_check[] = "test_decrypt.png";

	
	// Added by LZAVALAM'
	unsigned char *matrx;
	int p,j;
	// END ADDED by LZAVALAM
	
	
	unsigned long rk[RKLENGTH(KEYBITS)];
	unsigned char key[KEYLENGTH(KEYBITS)];
	//unsigned int i;
	int i; //CHANGED

	int nrounds;
	FILE *input_file, *output_file;
	unsigned char plaintext[16*N_FRAMES];
	unsigned char plaintext2[16];
	unsigned char pt[16];
	
	
	unsigned char ciphertext[16*N_FRAMES];
	unsigned char ciphertext2[16];

	//set the number of threads for openmp to use
	//by default we set this to the number of processors 
	//but of course you are free to change this number
	omp_set_num_threads(N_PROC);

	//you can uncomment the code below to verify 
	//openMP is working correctly
	
	#pragma omp parallel
	{
	  // Obtain thread number
	  int tid = omp_get_thread_num();
	  printf("Hello World from thread = %d\n", tid);

	  // Only master thread does this
	  if (tid == 0){
	    int nthreads = omp_get_num_threads();
	    printf("Number of threads = %d\n", nthreads);
	  }
	}
    // End tst  OPEN MP


    
	input_file = fopen(input, "r");
	if (!input_file) {
		printf("Error opening %s\n", input);
		return 0;
	}

	output_file = fopen(output, "w");
	if (!output_file) {
		printf("Error opening %s\n", output);
		return 0;
	}

	
	int count1 = 0, count2 = 0;
	int nread_last;
	unsigned int offset = 0;
	unsigned int nread;
	unsigned int npackets;
	unsigned int write_size;
	
	//--------------------------------------------------------------------------------
	SimRoiStart();		// START ROI OF SIMULATION OF SNIPERSIM
	//Map password to key
	#pragma omp parallel for
	for (i = 0; i < sizeof(key); i++)
		key[i] = *password != 0 ? *password++ : 0;					// Key contains the encryption key plus 0s to fix the value to 128/192/256 bits

	nrounds = rijndaelSetupEncrypt(rk, key, KEYBITS);
	while (!feof(input_file)) {
		nread = fread(plaintext, 1, sizeof(plaintext), input_file);
		if (nread == 0)
			break;

		npackets = ((nread-1)>>4)+1;
		write_size = npackets<<4;

		//#pragma omp parallel for //this doesn't help
		for( i = nread; i < write_size; i++) {
			plaintext[i] = ' ';
		}

		#pragma omp parallel for
		for(p=0; p<npackets; p++) {
			rijndaelEncrypt(rk, nrounds, plaintext+(p<<4), ciphertext+(p<<4));
		}

		if (fwrite(ciphertext,  write_size, 1, output_file) != 1) {
		    fclose(output_file);
		    return 1;
		}	
	}
    	SimRoiEnd();
	//----------------------------------------------------------------------------

	fclose(input_file);
	fclose(output_file);

	input_file = fopen(output, "r");
	if (!input_file) {
		printf("Error opening %s\n", output);
		return 0;
	}

	output_file = fopen(output_check, "w");
	if (!output_file) {
		printf("Error opening %s\n", output_check);
		return 0;
	}

	nrounds = rijndaelSetupDecrypt(rk, key, KEYBITS);
	while (1) {
		if (fread(ciphertext2, sizeof(ciphertext2), 1, input_file) != 1)
			break;
		rijndaelDecrypt(rk, nrounds, ciphertext2, plaintext2);
		fwrite(plaintext2, sizeof(plaintext2), 1, output_file);
	}
	fclose(input_file);
	fclose(output_file);

	return 0;
}

