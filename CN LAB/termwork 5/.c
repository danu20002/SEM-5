#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define KEY_LENGTH  2048


void generate_key_pair() {
    RSA *keypair = RSA_new();
    BIGNUM *bne = BN_new();
    int ret = 0;
    unsigned long e = RSA_F4;

    ret = BN_set_word(bne, e);
    if (ret != 1) {
        printf("Failed to set exponent\n");
        exit(EXIT_FAILURE);
    }

    ret = RSA_generate_key_ex(keypair, KEY_LENGTH, bne, NULL);
    if (ret != 1) {
        printf("Failed to generate RSA key pair\n");
        exit(EXIT_FAILURE);
    }

    FILE *public_key_file = fopen("public_key.pem", "w");
    PEM_write_RSA_PUBKEY(public_key_file, keypair);
    fclose(public_key_file);

    FILE *private_key_file = fopen("private_key.pem", "w");
    PEM_write_RSAPrivateKey(private_key_file, keypair, NULL, NULL, 0, NULL, NULL);
    fclose(private_key_file);

    RSA_free(keypair);
    BN_free(bne);
}


void encrypt_file(char *input_file_path, char *output_file_path) {
    RSA *public_key = NULL;
    FILE *input_file = NULL;
    FILE *output_file = NULL;
    unsigned char input_data[KEY_LENGTH / 8] = {0};
    unsigned char encrypted_data[KEY_LENGTH / 8] = {0};
    int bytes_read = 0;
    int encrypted_data_len = 0;

    // Read public key from file
    FILE *public_key_file = fopen("public_key.pem", "r");
    if (!public_key_file) {
        printf("Failed to open public key file\n");
        exit(EXIT_FAILURE);
    }

    public_key = PEM_read_RSA_PUBKEY(public_key_file, NULL, NULL, NULL);
    fclose(public_key_file);

    if (!public_key) {
        printf("Failed to read public key\n");
        exit(EXIT_FAILURE);
    }

   
    input_file = fopen(input_file_path, "rb");
    if (!input_file) {
        printf("Failed to open input file\n");
        exit(EXIT_FAILURE);
    }

    output_file = fopen(output_file_path, "wb");
    if (!output_file) {
        printf("Failed to open output file\n");
        exit(EXIT_FAILURE);
    }

   
    while ((bytes_read = fread(input_data, 1, sizeof(input_data), input_file)) > 0) {
        encrypted_data_len = RSA_public_encrypt(bytes_read, input_data, encrypted_data, public_key, RSA_PKCS1_PADDING);
        if (encrypted_data_len == -1) {
            printf("Failed to encrypt input data\n");
            exit(EXIT_FAILURE);
        }
        fwrite(encrypted_data, 1, encrypted_data_len, output_file);
    }

   
    fclose(input_file);
    fclose(output_file);
    RSA_free(public_key);
}


void decrypt_file(char *input_file_path, char *output_file_path) {
    RSA *private_key = NULL;
    FILE *input_file = NULL;
    FILE *output_file = NULL;
    unsigned char input_data[KEY_LENGTH / 8] = {0};
    unsigned char decrypted
