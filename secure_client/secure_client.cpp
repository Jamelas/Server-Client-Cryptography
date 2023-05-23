//////////////////////////////////////////////////////////////////////////////////////////////
// TCP CrossPlatform CLIENT v.1.0 (towards IPV6 ready)
// compiles using GCC
//
//
// References: https://msdn.microsoft.com/en-us/library/windows/desktop/ms738520(v=vs.85).aspx
//             http://long.ccaba.upc.edu/long/045Guidelines/eva/ipv6.html#daytimeServer6
//             Andre Barczak's tcp client codes
//
// Author: Napoleon Reyes, Ph.D.
//         Massey University, Albany
//
//////////////////////////////////////////////////////////////////////////////////////////////

#define USE_IPV6 true
#define DEFAULT_PORT "1234"

#if defined __unix__ || defined __APPLE__
#include <unistd.h>
  #include <errno.h>
  #include <stdlib.h>
  #include <stdio.h>
  #include <string.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <netdb.h> //used by getnameinfo()
  #include <cstdio>
  #include <iostream>
#elif defined _WIN32
#include <winsock2.h>
#include <ws2tcpip.h> //required by getaddrinfo() and special constants
#include <stdlib.h>
#include <stdio.h>
#include <cstdio>
#include <iostream>
#define WSVERS MAKEWORD(2,2) /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
//The high-order byte specifies the minor version number;
//the low-order byte specifies the major version number.

WSADATA wsadata; //Create a WSADATA object called wsadata.
#endif

//////////////////////////////////////////////////////////////////////////////////////////////


enum CommandName{USER, PASS, SHUTDOWN};

using namespace std;
/////////////////////////////////////////////////////////////////////

void printBuffer(const char *header, char *buffer){
    cout << "------" << header << "------" << endl;
    for(unsigned int i=0; i < strlen(buffer); i++){
        if(buffer[i] == '\r'){
            cout << "buffer[" << i << "]=\\r" << endl;
        } else if(buffer[i] == '\n'){
            cout << "buffer[" << i << "]=\\n" << endl;
        } else {
            cout << "buffer[" << i << "]=" << buffer[i] << endl;
        }
    }
    cout << "---" << endl;
}


/////////////////////////////////////////////////////////////////////
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
    unsigned long long int e;
    unsigned long long int n;
} server_public_key;

struct {
    unsigned long long int e = 1151;
    unsigned long long int n = 86881;
} eCA; //public key of CA


// Generate random value nonce for Initialisation Vector
unsigned long long int nonce;

/////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[]) {

    char portNum[12];

#if defined __unix__ || defined __APPLE__
    int s;
#elif defined _WIN32
    SOCKET s;
#endif

#define BUFFER_SIZE 500
//remember that the BUFFER_SIZE has to be at least big enough to receive the answer from the server
#define SEGMENT_SIZE 70
//segment size, i.e., if fgets gets more than this number of bytes it segments the message

    char send_buffer[BUFFER_SIZE],receive_buffer[BUFFER_SIZE];
    int n,bytes;

    char serverHost[NI_MAXHOST];
    char serverService[NI_MAXSERV];
    srand(time(NULL));


#if defined __unix__ || defined __APPLE__
    //nothing to do here

#elif defined _WIN32
//********************************************************************
// WSSTARTUP
//********************************************************************

//********************************************************************
// WSSTARTUP
/*  All processes (applications or DLLs) that call Winsock functions must
  initialize the use of the Windows Sockets DLL before making other Winsock
  functions calls.
  This also makes certain that Winsock is supported on the system.
*/
//********************************************************************
    int err;

    err = WSAStartup(WSVERS, &wsadata);
    if (err != 0) {
        WSACleanup();
        /* Tell the user that we could not find a usable */
        /* Winsock DLL.                                  */
        printf("WSAStartup failed with error: %d\n", err);
        exit(1);
    }


    if(USE_IPV6){
        printf("\n=== IPv6 ===");
    } else { //IPV4

        printf("\n=== IPv4 ===");
    }

//********************************************************************
/* Confirm that the WinSock DLL supports 2.2.        */
/* Note that if the DLL supports versions greater    */
/* than 2.2 in addition to 2.2, it will still return */
/* 2.2 in wVersion since that is the version we      */
/* requested.                                        */
//********************************************************************
    printf("\n\n<<<TCP (CROSS-PLATFORM, IPv6-ready) CLIENT, by nhreyes>>>\n");

    if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wVersion) != 2) {
        printf("Could not find a usable version of Winsock.dll\n");
        WSACleanup();
        exit(1);
    }
    else{
        printf("\nThe Winsock 2.2 dll was initialised.\n");
    }

#endif


//********************************************************************
// set the socket address structure.
//********************************************************************
    struct addrinfo *result = NULL;
    struct addrinfo hints;
    int iResult;

    memset(&hints, 0, sizeof(struct addrinfo));


    if(USE_IPV6){
        hints.ai_family = AF_INET6;
        printf("\n=== IPv6 ===\n");
    } else { //IPV4
        hints.ai_family = AF_INET;
        printf("\n=== IPv4 ===\n");
    }

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    //hints.ai_flags = AI_PASSIVE;


//*******************************************************************
//	Dealing with user's arguments
//*******************************************************************

    //if there are 3 parameters passed to the argv[] array.
    if (argc == 3){
        sprintf(portNum,"%s", argv[2]);
        printf("\nUsing port: %s \n", portNum);
        iResult = getaddrinfo(argv[1], portNum, &hints, &result);
    } else {
        printf("USAGE: Client IP-address [port]\n"); //missing IP address
        sprintf(portNum,"%s", DEFAULT_PORT);
        printf("Default portNum = %s\n",portNum);
        printf("Using default settings, IP:127.0.0.1, Port:1234\n");
        iResult = getaddrinfo(NULL, portNum, &hints, &result);
    }

    if (iResult != 0) {
        printf("getaddrinfo failed: %d\n", iResult);
#if defined _WIN32
        WSACleanup();
#endif
        return 1;
    }


//*******************************************************************
//CREATE CLIENT'S SOCKET
//*******************************************************************

#if defined __unix__ || defined __APPLE__
    s = -1;
#elif defined _WIN32
    s = INVALID_SOCKET;
#endif

    s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

#if defined __unix__ || defined __APPLE__
    if (s < 0) {
      printf("socket failed\n");
      freeaddrinfo(result);
  	}
#elif defined _WIN32
    //check for errors in socket allocation
    if (s == INVALID_SOCKET) {
        printf("Error at socket(): %d\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        exit(1);//return 1;
    }
#endif


//*******************************************************************
//CONNECT
//*******************************************************************


    if (connect(s, result->ai_addr, result->ai_addrlen) != 0) {
        printf("\nconnect failed\n");
        freeaddrinfo(result);
#if defined _WIN32
        WSACleanup();
#endif
        exit(1);
    } else {
        char ipver[80];

        if (result->ai_family == AF_INET)
        {
            strcpy(ipver,"IPv4");
        }
        else if(result->ai_family == AF_INET6)
        {
            strcpy(ipver,"IPv6");
        }


#if defined __unix__ || defined __APPLE__
        int returnValue;
#elif defined _WIN32
        DWORD returnValue;
#endif

        memset(serverHost, 0, sizeof(serverHost));
        memset(serverService, 0, sizeof(serverService));

        returnValue=getnameinfo((struct sockaddr *)result->ai_addr, /*addrlen*/ result->ai_addrlen,
                                serverHost, sizeof(serverHost),
                                serverService, sizeof(serverService), NI_NUMERICHOST);

        if(returnValue != 0){

#if defined __unix__ || defined __APPLE__
            printf("\nError detected: getnameinfo() failed with error\n");
#elif defined _WIN32
            printf("\nError detected: getnameinfo() failed with error#%d\n",WSAGetLastError());
#endif
            exit(1);

        } else{
            printf("\nConnected to <<<SERVER>>> extracted IP address: %s, %s at port: %s\n", serverHost, ipver,/* serverService */ portNum);  //serverService is nfa
        }
    }


    // receive the Server's encrypted public key dCA(e, n)
    n = 0;
    while (1){
        bytes = recv(s, &receive_buffer[n], 1, 0);
        if ((bytes == SOCKET_ERROR) || (bytes == 0)) {
            printf("recv failed\n");
            exit(1);
        }
        if (receive_buffer[n] == '\n') { // end on a LF
            receive_buffer[n] = '\0';
            break;
        }
        if (receive_buffer[n] != '\r') { // ignore CRs
            n++;
        }
    }
    printf("Received Server's Certificate: PUBLIC_KEY %s\n",receive_buffer);

    //send acknowledgment
    printf("Sending reply to SERVER: ACK 226 Public Key received\n");
    sprintf(send_buffer, "ACK 226 Public Key received\r\n");
    bytes = send(s, send_buffer, strlen(send_buffer),0);
    if (bytes == SOCKET_ERROR) {
        printf("send failed\n");
        WSACleanup();
        exit(1);
    }

    n = 0;
    string::size_type sz = 0;
    unsigned long long server_key[2];
    char *ch;
    ch = strtok(receive_buffer," ");
    // split the buffer into separate encrypted values
    while(ch != NULL){
        server_key[n] = stoull (ch,&sz,0);
        ch = strtok(NULL, " ");
        n++;
    }

    // decrypt the Server's public key
    server_public_key.e = repeatSquare(server_key[0], eCA.e, eCA.n);
    server_public_key.n = repeatSquare(server_key[1], eCA.e, eCA.n);
    printf("Decrypted Server's Public Key: [e = %lld, n = %lld]\n", server_public_key.e, server_public_key.n);

    // encrypt nonce
    nonce = rand() % server_public_key.n; // nonce must be less than the value of n
    unsigned long long cipher;
    cipher = repeatSquare(nonce, server_public_key.e, server_public_key.n);

    // send the encrypted nonce
    printf("Sending encrypted Nonce to SERVER: NONCE %lld\n", cipher);
    sprintf(send_buffer, "%lld\r\n", cipher);
    bytes = send(s, send_buffer, strlen(send_buffer),0);
    if (bytes == SOCKET_ERROR) {
        printf("send failed\n");
        WSACleanup();
        exit(1);
    }

    // receive message (ACK 220) from Server
    n = 0;
    while (1){
        bytes = recv(s, &receive_buffer[n], 1, 0);
        if ((bytes == SOCKET_ERROR) || (bytes == 0)) {
            printf("recv failed\n");
            exit(1);
        }
        if (receive_buffer[n] == '\n') { // end on a LF
            receive_buffer[n] = '\0';
            break;
        }
        if (receive_buffer[n] != '\r') n++; // ignore CRs
    }
    printf("Received packet: %s\n", receive_buffer);


//*******************************************************************
//The client can now start sending encrypted messages to the Server
//
//Get input while user don't type "."
//*******************************************************************
    printf("\n--------------------------------------------\n");
    printf("you may now start sending commands to the <<<SERVER>>>\n");
    printf("\nType here:");
    memset(&send_buffer,0,BUFFER_SIZE);
    if(fgets(send_buffer,SEGMENT_SIZE,stdin) == NULL){
        printf("error using fgets()\n");
        exit(1);
    }

    char encrypted_message[BUFFER_SIZE];
    string temp_str;
    const char *char_array = NULL;
    unsigned long long int encrypt;

    while ((strncmp(send_buffer,".",1) != 0)) {

        fill_n(encrypted_message, strlen(encrypted_message), 0); // Clear any existing values

        for (int i = 0; i < strlen(send_buffer); i++) {
            if (i == 0) encrypt = nonce;
            else encrypt = encrypt ^ send_buffer[i-1];

            encrypt = repeatSquare(encrypt, server_public_key.e, server_public_key.n);
            temp_str = to_string(encrypt);
            char_array = temp_str.c_str();
            strcat(encrypted_message, char_array);
            strcat(encrypted_message, " ");
        }
        strcat(encrypted_message,"\r\n");

        //*******************************************************************
        //SEND
        //*******************************************************************

        bytes = send(s, encrypted_message, strlen(encrypted_message),0);
        printf("\nMSG SENT <--: %s\n",encrypted_message);//line sent
        printf("Message length: %d \n",(int)strlen(encrypted_message));



#if defined __unix__ || defined __APPLE__
        if (bytes == -1) {
	         printf("send failed\n");
    		 exit(1);
	      }
#elif defined _WIN32
        if (bytes == SOCKET_ERROR) {
            printf("send failed\n");
            WSACleanup();
            exit(1);
        }
#endif


        n = 0;
        while (1) {
            //*******************************************************************
            //RECEIVE
            //*******************************************************************
            bytes = recv(s, &receive_buffer[n], 1, 0);

#if defined __unix__ || defined __APPLE__
            if ((bytes == -1) || (bytes == 0)) {
	            printf("recv failed\n");
	         	exit(1);
	         }

#elif defined _WIN32
            if ((bytes == SOCKET_ERROR) || (bytes == 0)) {
                printf("recv failed\n");
                exit(1);
            }
#endif


            if (receive_buffer[n] == '\n') {  // end on a LF
                receive_buffer[n] = '\0';
                break;
            }
            if (receive_buffer[n] != '\r') n++; // ignore CR's
        }

        printf("\nMSG RECEIVED --> %s\n", receive_buffer);
        printf("--------------------------------------------\n");

        //get another user input
        memset(&send_buffer, 0, BUFFER_SIZE);
        printf("\nType here:");
        if(fgets(send_buffer,SEGMENT_SIZE,stdin) == NULL){
            printf("error using fgets()\n");
            exit(1);
        }

    }
    printf("\n--------------------------------------------\n");
    printf("<<<CLIENT>>> is shutting down...\n");

//*******************************************************************
//CLOSESOCKET
//*******************************************************************
#if defined __unix__ || defined __APPLE__
    close(s);//close listening socket
#elif defined _WIN32
    closesocket(s);//close listening socket
    WSACleanup(); /* call WSACleanup when done using the Winsock dll */
#endif


    return 0;
}