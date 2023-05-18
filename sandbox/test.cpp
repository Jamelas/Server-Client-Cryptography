#define USE_IPV6 false
#define DEFAULT_PORT "1234"
#define K_BITS 256 //Message is encrypted in blocks of k bits

#include <winsock2.h>
#include <ws2tcpip.h> //required by getaddrinfo() and special constants
#include <stdlib.h>
#include <stdio.h>
#include <cstdio>
#include <iostream>

using namespace std;


//
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
    IV = rand() % K_BITS;
    return IV;
}


struct {
    unsigned char input[K_BITS];
    unsigned char output[K_BITS];
} kbit_exchange;

//populate the kbit table
void initialise_kbit_table() {
    unsigned char output[K_BITS];
    int i = 0;
    while (i < K_BITS) {
        output[i] = rand();
        for (int j = 0; j < i; j++) {
            if (i == 0) break;
            if (output[j] == output[i]) {
                //cout << "DUPLICATE FOUND" << endl;
                output[i] = rand();
                j = 0;
            }
        }
        kbit_exchange.input[i] = (char)i;
        kbit_exchange.output[i] = output[i];
        i++;
    }
}



void create_cipher_text(int IV, char encrypted_message[200]) {
    unsigned char ciphered_message[200];
    ciphered_message[0] = (unsigned char) IV;
    int i = 0;
    while (i < strlen(encrypted_message)) {
        ciphered_message[i + 1] = encrypted_message[i] ^ ciphered_message[i];
        i++;
        ciphered_message[i + 1] = kbit_exchange.output[(int) ciphered_message[i]];
    }
}


int main() {

    srand(time(NULL));

    char send_buffer[500];
    fill_n(send_buffer, strlen(send_buffer), 0);

    char encrypted_message[500];
    fill_n(encrypted_message, strlen(encrypted_message), 0);

    initialise_kbit_table();

    int encrypted;
    string temp_str;
    const char *char_array = NULL;



    send_buffer[0] = 'h';
    send_buffer[1] = 'e';
    send_buffer[2] = 'l';
    send_buffer[3] = 'l';
    send_buffer[4] = 'o';
    send_buffer[5] = '!';
    send_buffer[6] = '\n';
     /*
    send_buffer[0] = 'A';
    send_buffer[1] = 'A';
    send_buffer[2] = 'A';
    send_buffer[3] = '\n';
*/



    int IV = generate_IV();



/////////////////////////////////////////////////////////////////////
    //RSA ENCRYPT
    for (int i = 0; i <= strlen(send_buffer); i++) {
        if (i == strlen(send_buffer)) {
            strcat(encrypted_message, "\0"); //strip '\n'
            break;
        } else {
            if (i == 0) {
                encrypted = IV;
                //encrypted = 230;
            }
            else {
                cout << send_buffer[i] << endl;
                encrypted = encrypted ^ send_buffer[i-1];

            }
            encrypted = repeatSquare(encrypted, public_key.e, public_key.n);
            temp_str = to_string(encrypted);
            char_array = temp_str.c_str();
            strcat(encrypted_message, char_array);
            strcat(encrypted_message, " ");
        }
    }
//////////////////////////////////////////////////////////////////////////



    cout << "Original message: " << send_buffer << endl;
    cout << "Encrypted message: " << encrypted_message << endl;
    cout << "The value of IV is: " << IV << endl;
    cout << endl << endl;


    char message[500];
    fill_n(message, strlen(message), 0);

    int decrypted[3];
    int cipher;
    bool is_IV = true;
    char hold[500];
    fill_n(hold, sizeof(message), 0);

    for (int i = 0; i < strlen(encrypted_message); i++) {
        fill_n(hold, strlen(hold), 0);


        if (i == strlen(encrypted_message)) {
            strcat(message, "\0"); //strip '\n'
            break;
        }
        if (is_IV) {
            while (encrypted_message[i] != ' ') {
                hold[i] = encrypted_message[i];
                i++;
            }
            //cout << "hold is: "<< hold << endl;
            cout << "IV before decryption is: " << hold << endl;
            cipher = stoi(hold);
            decrypted[0] = repeatSquare(stoi(hold), private_key.d, private_key.n);
            cout << "IV after rsa decryption is: " << decrypted[0] << endl << endl;
            //i++;
            is_IV = false;
        }

        else {

            int j = 0;
            while (encrypted_message[i] != ' ') {
                hold[j] = encrypted_message[i];
                i++;
                j++;
            }

            cout << "hold is: "<< hold << endl;



            //fill_n(hold, strlen(message), 0);
            //decrypted[0] = repeatSquare(decrypted[0], private_key.d, private_key.n);
            //cout << "cipher before decryption is: " << hold << endl;
            decrypted[1] = repeatSquare(stoi(hold), private_key.d, private_key.n);
            //cout << "cipher after rsa decryption is: " << decrypted[1] << endl << endl;


            decrypted[0] = decrypted[1] ^ cipher;
            cipher = stoi(hold);

            char test = decrypted[0];
            cout << "TEST TEST " << test << endl;
            temp_str = char(decrypted[0]);
            char_array = temp_str.c_str();
            strcat(message, char_array);

            //message[i] = test;
        }





    }

    cout << "Message after decryption is: " << message << endl;

}

