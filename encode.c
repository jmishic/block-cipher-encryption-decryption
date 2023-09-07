//
// encode.c
//
// Description: main file for encoding plaintext into a ciphertext
//
// @author: Justin Mishic
// @loginID: jfm9134
//
///////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>

#include "cbc_lib.h"

int main(int argc, char * argv[]){
        if(argc < 2){
                perror("FAILED\n");
                return EXIT_FAILURE;
        }
        char * destpath = argv[1];
        if(encode(destpath) == EXIT_SUCCESS){
                return EXIT_SUCCESS;
        }
        else{
                fprintf(stderr, "FAILED\n");
                return EXIT_FAILURE;
        }
}
