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
        kbit_exchange.input[output[i]] = (unsigned char)i;
        cout << "input " << i << " is: "<< (unsigned int)kbit_exchange.input[i] << endl;
        kbit_exchange.output[i] = output[i];
        cout << "output " << i << " is: "<< (unsigned int)kbit_exchange.output[i] << endl;
        cout << endl;
        i++;
    }
}



void create_cipher_text(int IV, char encrypted_message[200]) {
    unsigned char ciphered_message[200];
    const unsigned char *str = NULL;
    ciphered_message[0] = (unsigned char) IV;
    int i = 0;
    while (i < strlen(encrypted_message)) {
        ciphered_message[i + 1] = encrypted_message[i] ^ ciphered_message[i];
        //strcat(ciphered_message, to_string(ciphered_message[i + 1]));

        i++;
        ciphered_message[i + 1] = kbit_exchange.output[(int) ciphered_message[i]];
    }
//strcat(str, ciphered_message);
   // return str;
}


int main() {

    srand(time(NULL));

    char send_buffer[200];
    fill_n(send_buffer, strlen(send_buffer), 0);

    char encrypted_message[200];
    fill_n(encrypted_message, strlen(encrypted_message), 0);

    initialise_kbit_table();

    int encrypted;
    string temp_str;
    const char *char_array = NULL;


    /*
    send_buffer[0] = 'h';
    send_buffer[1] = 'e';
    send_buffer[2] = 'l';
    send_buffer[3] = 'l';
    send_buffer[4] = 'o';
    send_buffer[5] = '!';
     */
    send_buffer[0] = 'A';
    send_buffer[1] = 'A';
    send_buffer[2] = 'A';

    int IV = generate_IV();
    char c[200];
    c[0] = IV;
    //encrypted = IV ^ send_buffer[0];
    //cout << "ciphered[0] is: " << (int)ciphered[0] << endl;
/////////////////////////////////////////////////////////////////////
    //RSA ENCRYPT
    for (int i = 0; i <= strlen(send_buffer); i++) {
        if (i > strlen(send_buffer)) {
            strcat(encrypted_message, "\0"); //strip '\n'
            break;
        } else {
            if (i == 0) {
                encrypted = IV;
            }
            else {
                encrypted = c[i] ^ send_buffer[i];
                encrypted = kbit_exchange.output[encrypted];

            }
            encrypted = repeatSquare(encrypted, public_key.e, public_key.n);
            temp_str = to_string(encrypted);
            char_array = temp_str.c_str();
            strcat(encrypted_message, char_array);
            strcat(encrypted_message, " ");
            c[i+1] = encrypted;
        }
    }
//////////////////////////////////////////////////////////////////////////


// 1. Generate random k-bit number and store as IV (c0)


// 2. Calculate the ciphertext (message xor c0)


// 3. Calculate remaining ciphertext for block i (c(i) = m(i) xor c(i-1))


    cout << "Original message: " << send_buffer << endl;
    cout << "Encrypted message: " << encrypted_message << endl;
    cout << "The value of IV is: " << IV << endl;
    cout << endl << endl;

/*
    // Split each character into 4-bit blocks
    for (int i = 0; i < strlen(encrypted_message); i++) {
        unsigned char c = encrypted_message[i];

        if (c == ' ') continue;
        int block1 = (c >> 4) & 0x0F; // get the first 4 bits
        int block2 = c & 0x0F; // get the last 4 bits

        cout << "Character " << c << " is split into blocks " << block1 << " and " << block2 << std::endl;
    }
*/




    //cout << "New ciphered text is: " << create_cipher_text(IV, encrypted_message);

    char message[200];
    fill_n(message, strlen(message), 0);

    int decrypted[3];
    bool is_IV = true;
    char hold[200];
    fill_n(hold, strlen(message), 0);

    for (int i = 0; i < strlen(encrypted_message); i++) {
        if (i == strlen(encrypted_message)) {
            strcat(message, "\0"); //strip '\n'
            break;
        }
        while (is_IV) {
            while (encrypted_message[i] != ' ') {
                hold[i] = encrypted_message[i];
                i++;
            }
            //cout << "hold is: "<< hold << endl;
            decrypted[0] = repeatSquare(stoi(hold), private_key.d, private_key.n);
            //cout << "Before DEBUG: " << decrypted[0] << endl;
            i++;
            is_IV = false;
        }


        int j = 0;
        fill_n(hold, strlen(hold), 0);

        while (encrypted_message[i] != ' ') {
            hold[j] = encrypted_message[i];
            i++;
            j++;
        }
        cout << "hold is: "<< hold << endl;



        //fill_n(hold, strlen(message), 0);
        //decrypted[0] = repeatSquare(decrypted[0], private_key.d, private_key.n);
        cout << "decrypted[0] after rsa decryption is: " << decrypted[0] << endl;
        decrypted[1] = repeatSquare(stoi(hold), private_key.d, private_key.n);
        cout << "decrypted after rsa decryption is: " << decrypted[1] << endl;


        decrypted[2] = kbit_exchange.output[decrypted[1]] ^ decrypted[0];
        cout << "DECRYPTION 2: " << decrypted[2] <<  endl;

        temp_str = to_string(decrypted[2]);
        char_array = temp_str.c_str();
        strcat(message, char_array);
        decrypted[0] = stoi(hold);


    }

    cout << "Message after decryption is: " << message << endl;

}

