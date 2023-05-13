#define USE_IPV6 false
#define DEFAULT_PORT "1234"
#define K_BITS 8 //Message is encrypted in blocks of k bits

#include <winsock2.h>
#include <ws2tcpip.h> //required by getaddrinfo() and special constants
#include <stdlib.h>
#include <stdio.h>
#include <cstdio>
#include <iostream>

using namespace std;


unsigned long long int repeatSquare(unsigned long long int x, unsigned long long int e, unsigned long long int n) {
    unsigned long long int y = 1;
    while(e > 0) {
        if ((e % 2) == 0) {
            x = (x * x) % n;
            e = e / 2;
        } else {
            y = (x * y) % n;
            e = e - 1;
        }
    }
    return y;
}



struct {
    unsigned long long int e = 529;
    unsigned long long int n = 75301;
} public_key;

struct {
    unsigned long long int d = 24305;
    unsigned long long int n = 75301;
} private_key;



// Generate random k-bit number for Initialisation Vector
int generate_IV() {
    int IV;
    IV = rand() % (1 << K_BITS);
    return IV;
}


int main() {

    char send_buffer[200];
    char encrypted_message[200];
    int encrypted;
    string temp_str;
    const char *char_array = NULL;
    int IV = generate_IV();

    send_buffer[0] = 'h';
    send_buffer[1] = 'e';
    send_buffer[2] = 'l';
    send_buffer[3] = 'l';
    send_buffer[4] = 'o';
    send_buffer[5] = '!';

/////////////////////////////////////////////////////////////////////
    //RSA ENCRYPT
    fill_n(encrypted_message, strlen(encrypted_message), 0);
    for (int i = 0; i < strlen(send_buffer); i++) {
        if (i == strlen(send_buffer)-1) {
            strcat(encrypted_message, "\0"); //strip '\n'
            break;
        } else {
            encrypted = repeatSquare(send_buffer[i], public_key.e, public_key.n);
            temp_str = to_string(encrypted);
            char_array = temp_str.c_str();
            strcat(encrypted_message, char_array);
            strcat(encrypted_message, " ");
        }
    }
//////////////////////////////////////////////////////////////////////////


    cout << "Original message: " << send_buffer << endl;
    cout << "Encrypted message: " << encrypted_message << endl;

}
