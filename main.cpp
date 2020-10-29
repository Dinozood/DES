#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "string.h"
#include "fun.h"
#include "helpers.h"
#define BUFFER 1024

using namespace std;
int main(int argc, char* argv[]) {
    char *clean_key, plaintext[BUFFER] = {0}, plaintext_block[8] = {0};
    char matrix_clean_key[64] = {0};
    char *path_to_plaintext;
    char keys48b[16][48], permuted_plaintext_matrix[64], encrypted_matrix[64];;
    bool flag = false;
    opterr = 0;
    int rez = getopt_long(argc, argv, optString, longOpts, &longIndex);     //Принимаем ключи
    while (rez != -1) {
        switch (rez) {
            case '?':                                   //Если ключ не известен, говорим, что ошибка
                fprintf(stderr, "%s\n", "There is wrong key, Error");
                exit(-1);
            case 'h':
                cout << "usage: des [options] [keys]]\n"
                        "-k for key\n"
                        "-p for path with text file\n"
                        "-d for debug mode\n"
                        "-h for that msg";
                exit(0);
            case 'd':
                DEBUG = true;
                init_fun(DEBUG);
                break;
            case 'p':
                path_to_plaintext = optarg;
                break;
            case 'k':
                clean_key = optarg;
                check_clean_key(clean_key);
        }
        rez = getopt_long(argc, argv, optString, longOpts, &longIndex);
    }

    //shiff plaintext from file
    sniff_plaintext(plaintext, BUFFER, path_to_plaintext);
    FILE* path_to_encryption = generate_encrypted_file(path_to_plaintext);
    generate_keys(matrix_clean_key, clean_key, keys48b);

    //generate plaintext
    for (int i = 0; i < (BUFFER/8); i=i+8) {
        flag = false;
        for (int j = 0; j < 8; ++j) {
            flag = flag || plaintext[i+j];
        }
        if (flag) {
            generate_plaintext_block(plaintext, i, plaintext_block);

            plaintext_initial_permutation(plaintext_block, permuted_plaintext_matrix);

            encryprion(keys48b, permuted_plaintext_matrix, encrypted_matrix);

            print_encrypted_text(encrypted_matrix);

            save_encryption(encrypted_matrix, path_to_encryption);
        } else
            break;
    }

    cout << "End!" << endl;
    return 0;
}









