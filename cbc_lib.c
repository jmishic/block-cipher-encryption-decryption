//
// cbc_lib.c
//
// description: implements block cipher encryptions and decryptions along
// with infrastructure to encode text strings and decode ciphertext files.
// encodes streams of text strings into ciphertext and decodes streams of
// ciphertext back into text strings
//
// @author: Justin Mishic
// @loginID: jfm9134
//
////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cbc_lib.h"

#define BYTES_PER_BLOCK sizeof(long)            //<-num of bytes in block
#define BITS_PER_BYTE 8L                        //<-num of bits in byte
#define BITS_PER_BLOCK (BYTES_PER_BLOCK * BITS_PER_BYTE)        //<-num of bits in block
#define INPUT_SIZE (24 * BYTES_PER_BLOCK)       //<-base input size for stdin

static block64 key = 0x1234DeadBeefCafe;        //<-static key used throughout encrypt/decrypt
static const block64 INITIALIZATION_VECTOR = 0x0L;      //<-starting vector of hex 0

/**
 * roll_right performs a bit barrel roll on block left to right count number
 * of bits, and returns the resulting block value
 * @param block: block of bits to be moved
 * @param count: number of movements each bit is moved to the right
 * @return: the updated block after all the movements are performed
 */
static block64 roll_right(block64 block, size_t count){
        // new block initialized
        block64 temp_block = block >> count;
        // ex) 10101011, 2 = 11000000
        block64 left_block = block << (BITS_PER_BLOCK - count);
        // ex) 10101011, 2 = 00101010 or 11000000 = 11101010
        block64 new_block = temp_block | left_block;
        return new_block;
}

/**
 * roll_left performs a bit barrel roll on block right to left count number 
 * of bits, and returns the resulting block value
 * @param block: block of bits to be moved
 * @param count: number of movements each bit is moved to the left
 * @return: the updated block after all the movements are performed
 */
static block64 roll_left(block64 block, size_t count){
        // new block initialized
        block64 temp_block = block << count;
        // ex) 11110101, 3 = 00000111
        block64 right_block = block >> (BITS_PER_BLOCK - count);
        // ex) 11110101, 3 = 10101000 or 00000111 = 10101111
        block64 new_block = temp_block | right_block;
        return new_block;
}

/**
 * block_cipher_encrypt implememnts the block cipher encryption to enrypt the block 
 * using the key, and returns the resulting block value. the input block is a plaintext 
 * and the returned block is cipher text
 * @param block: block of bits to be manipulated
 * @param key: given key to XOR the block by
 * @return: newly encrypted block after 4 loop round is performed
 */
static block64 block_cipher_encrypt(block64 block, block64 key){
        // initializes new variable to avoid confusion
        block64 new_block = block;
        // processes block in a loop of 4 rounds
        for(int i = 0; i < 4; i++){
                // performs bit barrel roll 10 positions to the left
                new_block = roll_left(new_block, 10);
                // XORs the rolled result with the key value
                new_block = new_block ^ key;
        }
        return new_block;
}

/**
 * block_cipher_decrypt implements the block cipher decryption to decrypt the block using
 * the key, and returns the resulting block value. the input block is a cipher text and
 * the returned block is a plaintext
 * @param block: block of bits to be manipulated
 * @param key: given key to XOR the block by
 * @return: newly encrypted block after 4 loop round is performed
 */
static block64 block_cipher_decrypt(block64 block, block64 key){
        // initializes new variable to avoid confusion
        block64 new_block = block;
        // processes block in a loop of 4 rounds
        for(int i =0; i < 4; i++){
                // XORs the block with the key value
                new_block = new_block ^ key;
                // rolls the block back 10 positions to the right
                new_block = roll_right(new_block, 10);
        }
        return new_block;
}

/**
 * block64_to_string fills the data character array with bytes from the txt block64 object.
 * the data array must have been allocated and big enough to contain the block content
 * plus a NUL byte
 * @param txt: block of bytes to be converted into characters
 * @param data: array of each char that was converted
 */
static void block64_to_string(block64 txt, char * data){
        // loops through all 8 bytes in txt
        // shifts bits over and multiplies by 0xff to grab each byte in order
        for(size_t i = 0; i < BYTES_PER_BLOCK; i++){
                data[i] = txt & 0xff;
                txt = txt & 0xffffffffffffff00;
                txt >>= BITS_PER_BYTE;
        }
}

/**
 * cbc_encrypt encrpyts the text string using pIV and key, and returns an array of block64
 * also returns an updated *pIV that is the ciphertext input to the next stage, the length
 * of the array depends on the length of the text argument
 * @param text: array of characters in given file
 * @param pIV: array of block64 that have become ciphertext
 * @param key: block64 key used in encryption
 * @return: array of block64 blocks that have become ciphertext
 */
static block64 * cbc_encrypt(char * text, block64 * pIV, block64 key){
        // initializes array of block64 to be returned
        block64 * return_blocks = calloc(INPUT_SIZE, sizeof(block64));
        // keeps track of space allocated and current space for realloc
        size_t allocated_space = INPUT_SIZE * sizeof(block64);
        size_t space_filled = 0;
        // converts text into block64
        block64 * new_block = (void*)text;
        // had to allocate space for pIV for some reason
        pIV = calloc(1, sizeof(pIV));
        // loops through each block in the text
        for(size_t i = 0; i < ((strlen(text) / BITS_PER_BYTE)  + 1); i++){
                // XORs pIV with the block found
                *pIV ^= new_block[i];
                // updates space_filled and checks if limit is reached for reallocation
                space_filled += BITS_PER_BLOCK;
                if(space_filled >= allocated_space){
                        return_blocks = realloc(return_blocks, 2 * allocated_space);
                        allocated_space *= 2;
                }
                // adds encrypted block into array
                return_blocks[i] = block_cipher_encrypt(*pIV, key);
                // updates the pIV for next encryption
                *pIV = return_blocks[i];
        }
        free(pIV);
        return return_blocks;
}

/**
 * cbc_decrpyt decrypts the cipher array of count blocks using pIV and key, the function 
 * returns a text string representing the concatenation of the decrypted plaintexts of all
 * the blocks in the array. also returns an updated *pIV
 * @param ciphertext: the encrypted text in terms of block64 array
 * @param count: length of ciphertext array
 * @param pIV: initialization vector to XOR block by
 * @param key: key of block64 used in encrpytion and decryption
 * @return: string of plaintext after decrpytion is completed
 */
static char * cbc_decrypt(block64 * ciphertext, size_t count, block64 * pIV, block64 key){
        // allocates space for plaintext to be returned
        char * plaintext = calloc(INPUT_SIZE, sizeof(char));
        // keeps track of allocated space and current space being used
        size_t allocated_space = INPUT_SIZE * sizeof(char);
        size_t space_used = 0;
        // allocates space for pIV
        pIV = calloc(1, sizeof(pIV));
        // loops through num of blocks and decrpyts each adding to array
        for(size_t i = 0; i < count; i++){
                // allocates space for each new data piece
                char * data = calloc(BITS_PER_BYTE, sizeof(char));
                // decrypts blocks one at a time
                block64 new_block = block_cipher_decrypt(ciphertext[i], key);
                // XORs decrpyted blocks with pIV
                new_block ^= *pIV;
                // converts block to string and updates data
                block64_to_string(new_block, data);
                // updates pIV with original ciphertext value
                *pIV = ciphertext[i];
                // updates allocation space used and reallocates if needed
                space_used += BITS_PER_BLOCK;
                if(space_used >= allocated_space){
                        plaintext = realloc(plaintext, 2 * allocated_space);
                        allocated_space *= 2;
                }
                // concatenates data to end of plaintext and frees data to be used again
                strcat(plaintext, data);
                free(data);
        }
        free(pIV);
        return plaintext;
}

/**
 * encode function from cbc_lib.h
 */
int encode(const char * destpath){
        // allocates space for string 
        char * str = calloc(INPUT_SIZE, sizeof(char));
        // creates variables to keep track of space allocated and space used
        size_t allocated_space = INPUT_SIZE * sizeof(char);
        size_t space_filled = 0;
        // reinitializes iv
        block64 * iv = (void*)INITIALIZATION_VECTOR;
        // allocates space for block to be returned
        block64 * result_block = calloc(INPUT_SIZE, sizeof(block64));
        size_t count = 0;
        // gets values from stdin one block at a time
        while(fgets(str, BITS_PER_BYTE, stdin) != NULL){
                // encrypts each block
                block64 * block_array = cbc_encrypt(str, iv, key);
                // checks space and reallocates if necessary
                space_filled += BITS_PER_BLOCK;
                if(space_filled >= allocated_space){
                        result_block = realloc(result_block, 2 * allocated_space);
                        allocated_space *= 2;
                }
                // adds encrypted block to the returned block
                result_block[count] = block_array[0];
                // increases num of and frees blocks added
                count++;
                free(block_array);
        }
        //free(block_array);
        // opens file to write to
        FILE * fp = fopen(destpath, "wb");
        // writes encryption in binary to file
        fwrite(result_block, count, sizeof(block64), fp);
        // close and free remaining uses
        free(result_block);
        fclose(fp);
        free(str);
        perror("ok\n");
        return EXIT_SUCCESS;
}


/**
 * decode function from cbc_lib.h
 */
int decode(const char * sourcepath){
        // opens file
        FILE *fp = fopen(sourcepath, "rb");
        // allocates space for string
        // error message for no file
        if(fp == NULL){
                perror("FAILED\n");
                return EXIT_FAILURE;
        }
        // initialize string
        unsigned char str[BYTES_PER_BLOCK];
        // use memset instead of calloc because calloc wasn't working
        memset(str, 0, BYTES_PER_BLOCK);
        // reinitialize the iv
        block64 * iv = (void*)INITIALIZATION_VECTOR;
        size_t num_read = 0;
        // read from file until EOF is reached (NULL)
        while((num_read = fread(str, sizeof(unsigned char), BYTES_PER_BLOCK, fp)) > 0){
                // converts string into array of block64 for easy processing
                block64 * block = (block64 *)str;
                // calculate number of times to call decrypt
                size_t count = num_read / sizeof(block64);
                // decrypt the array of blocks
                char * plaintext = cbc_decrypt(block, count, iv, key);
                // print to stdout
                printf("%s", plaintext);
                free(plaintext);
        }
        fclose(fp);
        perror("ok\n");
        return EXIT_SUCCESS;
}
