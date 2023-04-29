#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

// Define the maximum trans length
#define MAX_TRANS_LENGTH 150

// Define the maximum number of transs that can be stored
#define MAX_TRANS 10

// Define the structure of a trans block
struct trans_block {
    int index;
    char trans[MAX_TRANS_LENGTH + 1];
    char prev_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    char hash[SHA256_DIGEST_LENGTH * 2 + 1];
};

// Define the global trans block array
struct trans_block trans_chain[MAX_TRANS];

// Define the current trans block index
int current_index = 0;

// Function to calculate the SHA256 hash of a given string
void sha256(char *string, char outputBuffer[SHA256_DIGEST_LENGTH * 2 + 1]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[SHA256_DIGEST_LENGTH * 2] = '\0';
}

// Function to add a new trans block to the chain
void add_trans_block(char *trans) {
    struct trans_block new_block;
    new_block.index = current_index;
    strncpy(new_block.trans, trans, MAX_TRANS_LENGTH);
    new_block.trans[MAX_TRANS_LENGTH] = '\0';
    strncpy(new_block.prev_hash, trans_chain[current_index - 1].hash, SHA256_DIGEST_LENGTH * 2 + 1);
    sha256((char *)&new_block, new_block.hash);
    trans_chain[current_index] = new_block;
    current_index++;
}

// Function to print the entire trans chain
void print_trans_chain() {
    int i;
    for (i = 0; i < current_index; i++) {
        printf("Block %d:\n", trans_chain[i].index);
        printf("Transcations: %s\n", trans_chain[i].trans);
        printf("Previous Hash: %s\n", trans_chain[i].prev_hash);
        printf("Hash: %s\n", trans_chain[i].hash);
        printf("\n");
    }
}

// Function to find a trans block by index
struct trans_block *find_trans_block(int index) {
    if (index >= 0 && index < current_index) {
        return &trans_chain[index];
    }
    return NULL;
}

// Function to delete a trans block by index
void delete_trans_block(int index) {
    if (index >= 0 && index < current_index) {
        int i;
        for (i = index; i < current_index - 1; i++) {
            trans_chain[i] = trans_chain[i + 1];
        }
        current_index--;
    }
}

// Function to edit a trans block by index
void edit_trans_block(int index, char *new_trans) {
    if (index >= 0 && index < current_index) {
        struct trans_block *block_to_edit = &trans_chain[index];
        strncpy(block_to_edit->trans, new_trans, MAX_TRANS_LENGTH);
        block_to_edit->trans[MAX_TRANS_LENGTH] = '\0';
        sha256((char *)block_to_edit, block_to_edit->hash);

        // update the hashes of subsequent blocks
        int i;
        for (i = index + 1; i < current_index; i++) {
            struct trans_block *current_block = &trans_chain[i];
            strncpy(current_block->prev_hash, (current_block - 1)->hash, SHA256_DIGEST_LENGTH * 2 + 1);
            sha256((char *)current_block, current_block->hash);
        }
    }
}

int main() {
    int choice, index;
    char trans[MAX_TRANS_LENGTH + 1];

    do {
        printf("Transcations Manager Menu:\n");
        printf("1. Add a trans\n");
        printf("2. See all transs\n");
        printf("3. Delete a trans\n");
        printf("4. Edit a trans\n");
        printf("5. Quit\n");
        printf("Enter your choice (1-5): ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Enter a trans (maximum %d characters): ", MAX_TRANS_LENGTH);
                scanf("%s", trans);
                add_trans_block(trans);
                printf("Transcations added successfully.\n\n");
                break;
            case 2:
                printf("Transcations Chain:\n");
                print_trans_chain();
                break;
            case 3:
                printf("Enter the index of the trans to delete: ");
                scanf("%d", &index);
                delete_trans_block(index);
                printf("Transcations deleted successfully.\n\n");
                break;
            case 4:
                printf("Enter the index of the trans to edit: ");
                scanf("%d", &index);
                printf("Enter the new trans (maximum %d characters): ", MAX_TRANS_LENGTH);
                scanf("%s", trans);
                edit_trans_block(index, trans);
                printf("Transcations edited successfully.\n\n");
                break;
            case 5:
                printf("Goodbye!\n");
                break;
            default:
                printf("Invalid choice. Please choose a number between 1 and 5.\n\n");
                break;
        }
    } while (choice != 5);

    return 0;
}
