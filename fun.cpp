//
// Created by 1 on 27.10.2020.
//
#include "fun.h"

bool debug_mode = false;

void init_fun(bool debug) {
    debug_mode = debug;
}

void check_clean_key(char *clean_key) {
    int length = 0;
    for (int i = 0; clean_key[i] != 0 ; ++i) {
        length++;
    }
    if (length > 8) {
        cout << "Key is too big, it'll be truncated from:" << endl;
        cout << clean_key << endl;
        clean_key[8] = 0;
        cout << "to: \n" << clean_key << endl;
    }
}

void sniff_plaintext(char *plaintext, int BUFFER, char *path_to_plaintext) {
    FILE *read_file;
    read_file = fopen (path_to_plaintext, "r");
    if (read_file == NULL) perror ("Error opening file");
    else
    {
        while ( ! feof (read_file) )
        {
            if ( fgets (plaintext, BUFFER, read_file) == NULL ) break;
            cout << "Plaintext is:\n" << plaintext << endl;
        }
        fclose (read_file);
    }
}

void generate_plaintext_block(char *plaintext, int plaintext_iter, char *plaintext_block) {
    for (int i = 0; i < 8; ++i) {
        plaintext_block[i] = plaintext[plaintext_iter+i];
    }
}

void generate_keys(char *matrix_clean_key, char *clean_key, char(&m)[16][48]) {
    unsigned char buff = 0;
    char keys48b[16][48] = {{0},{0}};

    char C[28] = {0}, D[28] = {0};

    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            buff = clean_key[i] << j;
            buff = buff >> 7;
            matrix_clean_key[i*8+j] = buff + 48;
        }
    }
    if (debug_mode) {
        cout << "Key is:\n" << clean_key << endl << "Matrix for cleankey\n";
        for (int i = 0; i < 8; ++i) {
            for (int j = 0; j < 8; ++j) {
                cout << matrix_clean_key[i*8+j] << '\t';
            }
            cout << "\n";
        }
        cout << '\n';
    }

    //permutated choice 1
    for (int i = 0; i < 28; ++i) {
        C[i] = matrix_clean_key[__K1P[i]-1];
        D[i] = matrix_clean_key[__K2P[i]-1];
    }
    if (debug_mode) {
        cout << "after PC-1\n"
                "C0\tD0\n";
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 7; ++j) {
                cout << C[i*7+j];
            }
            cout << "\t";
            for (int j = 0; j < 7; ++j) {
                cout << D[i*7+j];
            }
            cout << "\n";
        }
    }
    char shift_step = 0;

    //PC2
    for (int i = 0; i < 16; ++i) {
        //shift
        switch(i) {
            case 0: case 1: case 8: case 15: shift_step = 1; break;
            default: shift_step = 2; break;
        }
        if (shift_step == 1){
            char trash_c=0, trash_d=0;
            trash_c = C[0]; trash_d = D[0];
            for (int j = 0; j < 27; ++j) {
                C[j] = C[j+1];
                D[j] = D[j+1];
            }
            C[27] = trash_c; D[27] = trash_d;
        }
        if (shift_step == 2) {
            char trash_c=0, trash_d=0;
            trash_c = C[0]; trash_d = D[0];
            for (int j = 0; j < 27; ++j) {
                C[j] = C[j+1];
                D[j] = D[j+1];
            }
            C[27] = trash_c; D[27] = trash_d;
            trash_c = C[0]; trash_d = D[0];
            for (int j = 0; j < 27; ++j) {
                C[j] = C[j+1];
                D[j] = D[j+1];
            }
            C[27] = trash_c; D[27] = trash_d;
        }
        if (debug_mode) {
            cout << endl << "after shift " << i << "\n"
                    "C" << i+1 <<"\tD"<< i+1 <<"\n";
            for (int i = 0; i < 4; ++i) {
                for (int j = 0; j < 7; ++j) {
                    cout << C[i*7+j];
                }
                cout << "\t";
                for (int j = 0; j < 7; ++j) {
                    cout << D[i*7+j];
                }
                cout << "\n";
            }
        }
        //pc-2
        for (int j = 0; j < 48; ++j) {
            if (__CP[j] < 28) {
                keys48b[i][j] = C[__CP[j]-1];
            }
            if (__CP[j] == 28){
                keys48b[i][j] = C[27];
            }
            if (__CP[j] > 28) {
                keys48b[i][j] = D[(__CP[j]-1)%28];
            }
        }
    }
    if (debug_mode) {
        /*for (int i = 0; i < 16; ++i) {
            cout << endl << "key " << i+1 << endl;
            for (int j = 0; j < 6; ++j) {
                for (int k = 0; k < 8; ++k) {
                    cout << keys48b[i][j*8+k];
                }
                cout << endl;
            }
            cout << endl;
        }*/
        cout << endl;
        for (int i = 0; i < 4; ++i) {
            cout << "Key " << i*4+1 << "\t\t" << "Key " << i*4+2 << "\t\t" << "Key " << i*4+3 << "\t\t"
                 << "Key " << i*4+4 << endl;
            for (int j = 0; j < 6; ++j) {
                for (int k = 0; k < 8; ++k) {
                    cout << keys48b[i*4][j*8+k];
                }
                cout <<'\t';
                for (int k = 0; k < 8; ++k) {
                    cout << keys48b[i*4+1][j*8+k];
                }
                cout <<'\t';
                for (int k = 0; k < 8; ++k) {
                    cout << keys48b[i*4+2][j*8+k];
                }
                cout <<'\t';
                for (int k = 0; k < 8; ++k) {
                    cout << keys48b[i*4+3][j*8+k];
                }
                cout << endl;
            }
        }
        cout << endl;
    }
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 48; ++j) {
            m[i][j] = keys48b[i][j];
        }
    }
}

void plaintext_initial_permutation(char *plaintext, char *playntext) {
    cout << "Plaintext matrix:" << endl;
    char matrix_permutated_plaintext[64] = {0};
    char matrix_plaintext[64] = {0};
    unsigned char buff = 0;

    //transform to bite matrix
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            buff = plaintext[i] << j;
            buff = buff >> 7;
            matrix_plaintext[i * 8 + j] = buff + 48;
        }
    }
    if (debug_mode) {
        for (int i = 0; i < 8; ++i) {
            for (int j = 0; j < 8; ++j) {
                cout << matrix_plaintext[i * 8 + j] << '\t';
            }
            cout << endl;
        }
    }

    //initial permutation
    for (int i = 0; i < 64; ++i) {
        matrix_permutated_plaintext[i] = matrix_plaintext[__IP[i]-1];
    }
    if (debug_mode) {
        cout << endl << "Permutated plaintext:" << endl;
        for (int i = 0; i < 8; ++i) {
            for (int j = 0; j < 8; ++j) {
                cout << matrix_permutated_plaintext[i * 8 + j] << '\t';
            }
            cout << endl;
        }
    }
    for (int i = 0; i < 64; ++i) {
        playntext[i] = matrix_permutated_plaintext[i];
    }
}

void encryprion(char (&keys48b)[16][48], char *permuted_plaintext_matrix, char *encrypted_matrix) {
    unsigned char L[32] = {0}, R[32] = {0}, past_R[32] = {0}, result_plaintext[64] = {0},
    expansioned_R[48] = {0}, s_boxes[32] = {0}, s_matrix[32] = {0};
    //initial initialisation of L&R blocks
    for (int i = 0; i < 32; ++i) {
        L[i] = permuted_plaintext_matrix[i];
        R[i] = permuted_plaintext_matrix[i+32];
    }

    for (int i = 0; i < 16; ++i) {
        //expansion of R block, from 32 to 48 bit
        for (int j = 0; j < 48; ++j) {
            expansioned_R[j] = R[__EP[j]-1];
        }
        if (debug_mode) {
            cout << endl << "Expansioned R block at " << i << " step" << endl;
            for (int j = 0; j < 6; ++j) {
                for (int k = 0; k < 8; ++k) {
                    cout << expansioned_R[j*8+k] << '\t';
                }
                cout << endl;
            }
        }

        //xor with key
        for (int j = 0; j < 48; ++j) {
            expansioned_R[j] = (static_cast<unsigned int>(expansioned_R[j] - 48) xor static_cast<unsigned int>
                    (keys48b[i][j] - 48)) + 48;
        }
        if (debug_mode) {
            cout << endl;
            cout << "xored R block and key at " << i << " step" << endl;
            for (int j = 0; j < 8; ++j) {
                for (int k = 0; k < 6; ++k) {
                    cout << expansioned_R[j*6+k] << '\t';
                }
                cout << endl;
            }
        }

        //s_boxes
        int row, column;
        unsigned char buff;
        for (int j = 0; j < 8; ++j) {
            row = (expansioned_R[j*6]-48)*2+(expansioned_R[j*6+5]-48);
            column = (expansioned_R[j*6+1]-48)*8 + (expansioned_R[j*6+2]-48)*4 + (expansioned_R[j*6+3]-48)*2 + (expansioned_R[j*6+4]-48);
            for (int k = 0; k < 4; ++k) {
                buff = __Sbox[j][row][column];
                buff = buff << (k+4);
                buff = buff >> 7;
                s_boxes[j * 4 + k] = buff + 48;
            }
        }
        if (debug_mode) {
            cout << endl;
            cout << "s_boxes at " << (int)i << " step is:" << endl;
            for (int j = 0; j < 8; ++j) {
                for (int k = 0; k < 4; ++k) {
                    cout << s_boxes[j * 4 + k] << '\t';
                }
                cout << endl;
            }
            cout << endl;
        }

        //permutation
        for (int j = 0; j < 32; ++j) {
            s_matrix[j] = s_boxes[__P[j]-1];
        }
        if (debug_mode) {
            cout << "S_matrix after permutation at " << i << " round is" << endl;
            for (int j = 0; j < 4; ++j) {
                for (int k = 0; k < 8; ++k) {
                    cout << s_matrix[j*8+k] << '\t';
                }
                cout << endl;
            }
        }

        for (int j = 0; j < 32; ++j) {
            past_R[j] = R[j];
        }

        //xor L and S_matrix
        for (int j = 0; j < 32; ++j) {
            R[j] = (static_cast<unsigned int>(L[j] - 48) xor static_cast<unsigned int>
            (s_matrix[j] - 48)) + 48;
            L[j] = past_R[j];
        }
        if (debug_mode) {
            cout << endl;
            cout << "L and R block after " << i << " round" << endl;
            for (int j = 0; j < 4; ++j) {
                for (int k = 0; k < 8; ++k) {
                    cout << L[j*8+k];
                }
                cout << '\t';
                for (int k = 0; k < 8; ++k) {
                    cout << R[j*8+k];
                }
                cout << endl;
            }
        }


    }
    //final permutation
    for (int i = 0; i < 32; ++i) {
        result_plaintext[i] = R[i];
        result_plaintext[i + 32] = L[i];
    }
    for (int i = 0; i < 64; ++i) {
        encrypted_matrix[i] = result_plaintext[__FP[i]-1];
    }
    if (debug_mode) {
        cout << endl << "encrypted message is: " << endl;
        for (int i = 0; i < 8; ++i) {
            for (int j = 0; j < 8; ++j) {
                cout << encrypted_matrix[i*8+j] <<'\t';
            }
            cout << endl;
        }
        cout << endl;
    }

}

void print_encrypted_text(char *encrypted_matrix) {
    unsigned char buff = 0, chr = 0;
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            buff = encrypted_matrix[i*8+j] - 48;
            chr = chr << 1;
            chr = chr + buff;
        }
        cout << std::hex << static_cast<int>(chr) << '\t';
        chr = 0;
    }
    cout << std::dec << endl;
}


FILE *generate_encrypted_file(char *path_to_plaintext) {
    int iter = 0, i=0;
    char format[32] = {0};
    char full_name[4096] = {0};
    while (path_to_plaintext[iter] != 0)
        ++iter;

    for (iter; iter > 0; --iter) {
        format[31-i] = path_to_plaintext[iter];
        ++i;
        if (path_to_plaintext[iter] == '.')
            break;
    }

    for (int j = 0; j < 32; ++j) {
        if (format[0] != 0)
            break;
        for (int k = 0; k < 32; ++k) {
            format[k] = format[k+1];
        }
    }
    for (int j = 0; j < iter; ++j) {
        full_name[j] = path_to_plaintext[j];
    }
    full_name[iter] = '_';
    full_name[iter+1] = 'e';
    full_name[iter+2] = 'n';
    full_name[iter+3] = 'c';
    full_name[iter+4] = 'r';
    i = 0;

    for (int j = iter+5; format[i] !=0 ; ++j) {
        full_name[j] = format[i];
        ++i;
    }

    FILE* path_to_encr = fopen(full_name, "w");
    return path_to_encr;
}

void save_encryption(char *matrix, FILE *path_to_plaintext) {
    unsigned char buff = 0, chr = 0;
    char block[8];
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            buff = matrix[i*8+j] - 48;
            chr = chr << 1;
            chr = chr + buff;
        }
        fputc(chr, path_to_plaintext);
        chr = 0;
    }
}