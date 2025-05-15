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
        printf("[PID %d] Will sleep for 3600 seconds\n", getpid());
        sleep(3600);
    } else {
        printf("[PID %d] Will read from stdin\n", getpid());
        char buffer[256];
        fgets(buffer, sizeof(buffer), stdin);
    }
    
    return 0;
}
