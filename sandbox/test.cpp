#define K_BITS 256 //Message is encrypted in blocks of k bits

#include <winsock2.h>
#include <stdlib.h>
#include <iostream>

using namespace std;


// Encrypt message/decrypt cipher
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
    IV = rand() % 256;
    return IV;
}


int main() {

    srand(time(NULL));

    char send_buffer[500];
    fill_n(send_buffer, strlen(send_buffer), 0);

    char encrypted_message[500];
    fill_n(encrypted_message, strlen(encrypted_message), 0);


    int encrypt;
    string temp_str;
    const char *char_array = NULL;



    send_buffer[0] = 'h';
    send_buffer[1] = 'e';
    send_buffer[2] = 'l';
    send_buffer[3] = 'l';
    send_buffer[4] = 'o';
    send_buffer[5] = '!';
    send_buffer[6] = '\n';





///////////////////////////  INPUT  ///////////////////////////


    for (int i = 0; i < strlen(send_buffer); i++) {
        if (i == strlen(send_buffer)) {
            strcat(encrypted_message, "\0"); //strip '\n'
            break;
        } else {
            if (i == 0) {
                encrypt = generate_IV();
            }
            else {
                encrypt = encrypt ^ send_buffer[i-1];
            }

            encrypt = repeatSquare(encrypt, public_key.e, public_key.n);
            temp_str = to_string(encrypt);
            char_array = temp_str.c_str();
            strcat(encrypted_message, char_array);
            strcat(encrypted_message, " ");
        }
    }

    cout << "Original message: " << send_buffer;
    cout << "Encrypted message: " << encrypted_message << endl;
///////////////////////////////////////////////////////////////





///////////////////////////  OUTPUT  //////////////////////////
    char receive_buffer[500];
    fill_n(receive_buffer, strlen(receive_buffer), 0);

    int decrypted;
    int cipher;
    bool is_IV = true;

    char hold[500];


    for (int i = 0; i < strlen(encrypted_message); i++) {
        fill_n(hold, strlen(hold), 0);


        if (i == strlen(encrypted_message)) {
            strcat(receive_buffer, "\0"); //strip '\n'
            break;
        }

        //Find IV value.
        if (is_IV) {
            while (encrypted_message[i] != ' ') {
                hold[i] = encrypted_message[i];
                i++;
            }

            cipher = stoll(hold);
            is_IV = false;
        }

        else {
            // extract the next character from the buffer
            int j = 0;
            while (encrypted_message[i] != ' ') {
                hold[j] = encrypted_message[i];
                i++;
                j++;
            }

            decrypted = (repeatSquare(stoll(hold), private_key.d, private_key.n)) ^ cipher;
            cipher = stoll(hold);


            temp_str = char(decrypted);
            char_array = temp_str.c_str();
            strcat(receive_buffer, char_array);
        }

    }
    ///////////////////////////////////////////////////////////////


    cout << "Message after decryption is: " << receive_buffer << endl;

}
