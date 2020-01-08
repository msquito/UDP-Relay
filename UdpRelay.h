/* H Ryan Harasimowicz  | 9421622
 * css503 spring 2015   | Dr.Parsons
 * prog4 UdpRelay       | 2015.06.08 */

#ifndef PROG4_UDPRELAY_H
#define PROG4_UDPRELAY_H

#include <stdio.h>
#include <string>
#include <iostream>
#include <pthread.h>
#include <signal.h>
#include <unordered_map>
#include <unordered_set>
#include "Socket.h"
#include "UdpMulticast.h"

typedef std::unordered_multimap<char*, char*> charmap;

class UdpRelay {

public:

    UdpRelay(const char *);
    ~UdpRelay();

private:

    static const char* PORT;

    void UdpAddRemIP(std::string);
    void UdpDelRemIP(std::string);
    void UdpShow();
    void UdpHelp();
    void UdpQuit();

#pragma mark helper functions

    void error(const char *);

#pragma mark message helper functions

    string    msgHeaderGet(const char *);
    string  msgMessageGet(const char *);
    bool    msgRelayFind(char *);
    string  msgRelayAdd(char *);
    int msgGetLength(string);
    string msgCharToString(char*);
    char* msgStringToChar(string);

#pragma mark thread initialization methods

    static void *call_commandFunc(
            void *arg) { return ((UdpRelay *) arg)->commandFunc(); }
    void *commandFunc();
    static void *call_acceptFunc(
            void *arg) { return ((UdpRelay *) arg)->acceptFunc(); }
    void *acceptFunc();
    static void *call_relayInFunc(
            void *arg) { return ((UdpRelay *) arg)->relayInFunc(); }
    void *relayInFunc();
    static void *call_relayOutFunc(
            void *arg) { return ((UdpRelay *) arg)->relayOutFunc(); }
    void *relayOutFunc();

    bool live{true};

    int TcpClientSD;
    int TcpServerSD;
    int UdpClientSD;

    unordered_set<int> TCP_ClientSDs;
//    unordered_set<string> TCP_ClientNames;

    unordered_map< int, string > TCP_SSdToClient;
    unordered_map< string, int > TCP_ClientToCSd;
    unordered_map< int, string > TCP_CSdToServer;
    unordered_map< string, int > TCP_ServerToCSd;


    Socket *masterSocket;
    UdpMulticast *UdpMC;

    char bufferTCPInbound   [BUFSIZ];
    char bufferUdpInbound   [BUFSIZ];

    char *remoteIpAddress;
    char hostname [BUFSIZ];

    string groupIp;
    string groupPort;

    charmap TCP_SNameToCName;

    int TcpReceive( int, char * );
    void TcpSend( int, const char * );
};


#endif //PROG4_UDPRELAY_H
