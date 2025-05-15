#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

int main() {
    // Seed random number generator
    srand(time(NULL));
    
    // Randomly choose between sleep or read
    int choice = rand() % 2;
    
    if (choice) {
        printf("Will sleep for 3600 seconds\n");
        sleep(3600);
    } else {
        printf("Will read from stdin\n");
        char buffer[256];
        fgets(buffer, sizeof(buffer), stdin);
    }
    
    return 0;
}
