#include <stdio.h>
#include <unistd.h>

int main() {
    // Wait for 10 seconds
    sleep(10);
    
    // Print message before reading
    printf("now reading\n");
    
    // Read from stdin
    char buffer[256];
    fgets(buffer, sizeof(buffer), stdin);
    
    return 0;
}
