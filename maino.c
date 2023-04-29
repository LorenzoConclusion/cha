#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

#define MAX_PENDING_TRANSACTIONS 100
#define HASH_SIZE 64

struct Transaction {
    int amount;
    char sender[50];
    char receiver[50];
};

struct PendingList {
    struct Transaction transactions[MAX_PENDING_TRANSACTIONS];
    int count;
};

struct Block {
    int index;
    char timestamp[25];
    char hash[HASH_SIZE];
    char previous_hash[HASH_SIZE];
    struct PendingList pending_list;
};

void sha256(char *blockchain, char *hash) {
    unsigned char temp[SHA256_DIGEST_LENGTH];
    SHA256(blockchain, strlen(blockchain), temp);
    int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hash[i * 2], "%02x", temp[i]);
    }
    hash[HASH_SIZE] = '\0';
}

void ajout_transaction(struct PendingList *pending_list) {
    time_t current_time = time(NULL);
    char *c_time_string = ctime(&current_time);
    c_time_string[strlen(c_time_string) - 1] = '\0';

    struct Transaction transaction;
    printf("Entrez le montant de la transaction: ");
    scanf("%d", &transaction.amount);
    printf("Entrez l'expéditeur de la transaction: ");
    scanf("%s", transaction.sender);
    printf("Entrez le destinataire de la transaction: ");
    scanf("%s", transaction.receiver);
    pending_list->transactions[pending_list->count++] = transaction;

    printf("La transaction a été ajoutée avec succès.\n");
}

void affiche(struct Block block) {
    printf("Index: %d\n", block.index);
    printf("Timestamp: %s\n", block.timestamp);
    printf("Hash: %s\n", block.hash);
    printf("Previous hash: %s\n", block.previous_hash);
    printf("Pending transactions:\n");
    int i;
    for (i = 0; i < block.pending_list.count; i++) {
        printf("Transaction #%d:\n", i + 1);
        printf("Amount: %d\n", block.pending_list.transactions[i].amount);
        printf("Sender: %s\n", block.pending_list.transactions[i].sender);
        printf("Receiver: %s\n", block.pending_list.transactions[i].receiver);
    }
}

void sauvgarder(struct Block block) {
    char blockchain[1024];
    sprintf(blockchain, "%d%s%s%s", block.index, block.timestamp, block.hash, block.previous_hash);

    char hash[HASH_SIZE + 1];
    sha256(blockchain, hash);

    char filename[] = "blockchain.txt";
    FILE *f = fopen(filename, "a");
    fprintf(f, "%d,%s,%s,%s,%s\n", block.index, block.timestamp, hash, block.hash, block.previous_hash);
    fclose(f);
}

int main() {
    struct Block block;
    block.index = 0;
    strcpy(block.timestamp, "2023-04-29 12:00:00");
    strcpy(block.hash, "0000000000000000000000000000000000000000000000000000000000000000");
    strcpy(block.previous_hash, "0000000000000000000000000000000000000000000000000000000000000000");
    block.pending_list.count = 0;

    ajout_transaction(&block.pending_list);
    affiche(block);
    sauvgarder(block);

    return 0;
}
