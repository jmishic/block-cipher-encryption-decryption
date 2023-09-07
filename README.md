# block-cipher-encryption-decryption
block cipher encryptions and decryptions along with infrastructure to encode text strings and decode ciphertext files.  encodes streams of text strings into ciphertext and decodes streams of ciphertext back into text strings

##Makefile
###Compilation
- gcc -ggdb -std=c99 -Wall -Wextra -pedantic  -c decode.c
- gcc -ggdb -std=c99 -Wall -Wextra -pedantic  -c cbc_lib.c
- gcc -ggdb -std=c99 -Wall -Wextra -pedantic -o decode decode.o cbc_lib.o  -lm
- gcc -ggdb -std=c99 -Wall -Wextra -pedantic -o encode encode.o cbc_lib.o  -lm
- gcc -ggdb -std=c99 -Wall -Wextra -pedantic  -c unit_test.c
- gcc -ggdb -std=c99 -Wall -Wextra -pedantic -o unit_test unit_test.o -lm
- 	'make allall' completed.

'gmakemake > Makefile' in command line to compile

##Encoding/Decoding process
- Uses bit manipulation tactics
- bit barrel roll

##Memory Allocation
- malloc, calloc, realloc used

