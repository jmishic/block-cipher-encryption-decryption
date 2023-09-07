//
// decode.c
//
// Description: main function for decoding ciphertext back into plaintext
//
// @author: Justin Mishic
// @loginID: jfm9134
//
////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>

#include "cbc_lib.h"

int main(int argc, char * argv[]){
        if(argc < 2){
                perror("FAILED\n");
                return EXIT_FAILURE;
        }
        char * sourcepath = argv[1];
        if(decode(sourcepath) == EXIT_SUCCESS){
                return EXIT_SUCCESS;
        }
        else{
                perror("usage: decode file-name # to standard input\n");
                return EXIT_FAILURE;
        }
}
