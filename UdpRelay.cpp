/* H Ryan Harasimowicz  | 9421622
 * css503 spring 2015   | Dr.Parsons
 * prog4 UdpRelay       | 2015.06.08 */

#include <iostream>
#include <string.h>
#include <sstream>
#include <pthread.h>
#include <iostream>
#include <iomanip>
#include "UdpRelay.h"


#define NO_ERROR 0
#define TCP_PORT 21622
#define IP_LNGTH 4
#define HDR_FRT_END 4

#pragma mark constructor/destructor

UdpRelay::UdpRelay(const char * grpIdGrpPort)  {

    signal(SIGPIPE, SIG_IGN);

    std::string groupIdGroupPort = (std::string) grpIdGrpPort;
    int argSeparator = groupIdGroupPort.find(":");
    groupIp = groupIdGroupPort.substr(0,argSeparator);
    groupPort = groupIdGroupPort.substr(argSeparator+1,5);

    gethostname(hostname, BUFSIZ);

    // spawn initial threads;
    pthread_t commandThread, acceptThread, relayInThread;

    int errorID = pthread_create(&commandThread, NULL, call_commandFunc, this);
    if (errorID != NO_ERROR){
        std::cerr << "failed to create commandThread..." << std::endl;
        exit(-1);
    }
    errorID = pthread_create(&acceptThread, NULL, call_acceptFunc, this);
    if (errorID != NO_ERROR){
        std::cerr << "failed to create acceptThread..." << std::endl;
        exit(-1);
    }
    errorID = pthread_create(&relayInThread, NULL, call_relayInFunc, this);
    if (errorID != NO_ERROR){
        std::cerr << "failed to create relayInThread..." << std::endl;
        exit(-1);
    }

    // report for console
    cout << "UdpRelay: booted up at " <<  grpIdGrpPort << endl;


    pthread_join(commandThread, NULL);
    pthread_join(acceptThread, NULL);
    pthread_join(relayInThread, NULL);
}

UdpRelay::~UdpRelay() {}

#pragma mark primary methods

/* Adds a TCP connection to a remote network segment or group whose
 * representative nodes IP address and TCP port are remoteIP and remoteTcpPort.
 * It then instantiates relayOutThread that keeps reading a UDP multicast
 * message through this TCP connection from remoteIp and multicasting the
 * message to the local group, (ie, groupIp)*/
void UdpRelay::UdpAddRemIP(string input) {
    // parse input
    int argSeparator = input.find(":");
    string remoteIp = input.substr(0, argSeparator);


    // store input
    remoteIpAddress = new char[remoteIp.size()+1];
    remoteIpAddress[remoteIp.size()]=0;
    memcpy(remoteIpAddress,remoteIp.c_str(),remoteIp.size());

    char* locHostname = new char [BUFSIZ];
    gethostname(locHostname, BUFSIZ);


    char* newConnection = new char [BUFSIZ];
    // adds TCP connection to remote network segment :)
    TcpClientSD = masterSocket->getClientSocket(remoteIpAddress);
    if (TcpClientSD < NO_ERROR){
        cerr << "UdpAddRemIp: ERROR - failed getClientSocket" << endl;
        exit(-1);
    }


    // prep sockadder struct for receipt of connection name
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    socklen_t Slen = sizeof(sa);
    getpeername(TcpClientSD, (struct sockaddr *) &sa, &Slen);

    // get connection name + announce registration
    char peer[NI_MAXSERV];
    int res = getnameinfo((struct sockaddr *) &sa, sizeof(sa), peer,
                          sizeof(peer), NULL, 0, 0);
    if (res) {
        error("UdpAddRemIp: ERROR - failed getnameinfo");
    }
    int hostTrunc = strlen(peer) - 8;
    string hostStr = msgCharToString(peer);
    hostStr.resize(hostTrunc);

    // register peer as a client
    TCP_ServerToCSd.insert(std::pair< string, int > ( hostStr, TcpClientSD));
    TCP_CSdToServer.insert(std::pair< int, string > (TcpClientSD, hostStr ));
    cout << "UdpRelay: registered " << hostStr << endl;
    // Membership for TCP ClientSocket <int>
    TCP_ClientSDs.insert(TcpClientSD);


    // todo see if this is used
    // maps uw1-320-04 : uw1-320-05
    // map this at Accept thread
    TCP_SNameToCName.insert(std::pair<char*, char*>( remoteIpAddress, locHostname));


    delete[] remoteIpAddress; // cleanup
    remoteIpAddress = NULL;
    delete[] locHostname;
    locHostname = NULL;
};

void UdpRelay::UdpDelRemIP(string input) {
    int how = 2;    // close both read and write
    if (TCP_ServerToCSd.find(input) != TCP_ServerToCSd.end()){
        int serverSocket = TCP_ServerToCSd.find(input)->second;
        int retVal = shutdown(serverSocket, how);
        if (retVal < NO_ERROR){
            error("UdpDelRemIP: ERROR on shutdown");
        }
        close(serverSocket);
        cout << "UdpRelay: deleted " << input << endl;
        TCP_ClientSDs.erase(TCP_ServerToCSd.find(input)->second);
        TCP_CSdToServer.erase(TCP_ServerToCSd.find(input)->second);
        TCP_ServerToCSd.erase(input);
    } else {
        cout << "UdpRelay: remote IP not connected" << endl;
    }
}

void UdpRelay::UdpShow() {
    cout << "UdpRelay: Currently attached outbound remote groups: " << endl;
    for(auto server : TCP_ServerToCSd) {
        cout << "\tserver socket: " << server.second
             << " connected to remote host: " << server.first << endl;
    }
    cout << "UdpRelay: Currently attached inbound remote groups: " << endl;

    for(auto client : TCP_ClientToCSd) {
        cout << "\tserver socket: " << client.second
        << " connected to remote host: " << client.first << endl;
    }
}

void UdpRelay::UdpHelp() {
    std::cout << "\tUdpRelay.commandThread accepts:" << std::endl;
    cout << "\t\tadd remoteIP:remoteTcpPort" << endl;
    cout << "\t\tdelete remoteIP" << endl;
    cout << "\t\tshow" << endl;
    cout << "\t\thelp" << endl;
    cout << "\t\tquit" << endl;

}

void UdpRelay::UdpQuit() {
    cout << "quit not implemented per prog4 option" << endl;

//    for(auto server : TCP_ServerToCSd) {
//        close(server.second);
//    }
//    for(auto client : TCP_ClientToCSd) {
//        close(client.second);
//    }
//    live = false;
//    delete UdpMC;
//    delete masterSocket;
}

#pragma mark helper functions

// error helper
void UdpRelay::error(const char *msg){
    cerr << msg << endl;
    exit(1);
}

// ROT called function to receive + announce
int UdpRelay::TcpReceive(int sSd, char *buf) {
    // start fresh...
    memset(buf, 0, BUFSIZ);

    // receive waits for message to arrive
    int receivedSize = recv(sSd, buf, BUFSIZ, MSG_WAITALL);
    if(receivedSize == 0){
        return 0;
    } else if (receivedSize < NO_ERROR) {
        error("TcpR: ERROR on recv");
    } else {
        // validate that this message hasn't been received...
        if (!msgRelayFind(buf)) {
            string bufMsg = msgMessageGet(buf);
            cout << "TCPR: UdpRelay: received " << strlen(buf)
                 << " bytes from " << TCP_SSdToClient.find(sSd)->second
                 << " msg = " << bufMsg << endl;
            return receivedSize;
        }
    }
}

void UdpRelay::TcpSend( int cSd, const char *buf ) {
    int sentChars = send(cSd, buf, BUFSIZ, MSG_NOSIGNAL | MSG_CONFIRM);
    // todo error-check send
}

#pragma mark message-helper functions

// isolate header data into own buffer
string UdpRelay::msgHeaderGet(const char *buffer) {
    char hops = buffer[3];

    if (buffer[0] == -32){
        if (buffer[1] == -31){
            if (buffer[2] == -30){
                if (hops > 0){
                    // include space for header front-end
                    int headerLength = 4 + (hops) * IP_LNGTH;
                    // isolate header + return
                    string header = buffer;
                    header.resize(headerLength);
                    return header;
                } else {
                    cerr << "msgHeaderGet: bad header[hops]" << endl;
                    return '\0';
                }
            } else {
                cerr << "msgHeaderGet: bad header[2]" << endl;
                return '\0';
            }
        } else {
            cerr << "msgHeaderGet: bad header[1]" << endl;
            return '\0';
        }
    } else {
        error( "msgHeaderGet: bad header[0]" );
    }
}

// isolate message from header data
string UdpRelay::msgMessageGet(const char *buffer) {
    // figure out header length
    size_t hops =  buffer[3];
    size_t headerLength = (HDR_FRT_END + (hops * IP_LNGTH));
    // truncate + return
    string bufStr = buffer;
    string message = bufStr.substr(headerLength,string::npos);
    return message;
}

// search for current Relay's GroupIp in header history
bool UdpRelay::msgRelayFind(char *hdrMsg){
    string hdrStr = msgHeaderGet(hdrMsg);
    if (hdrStr.find(groupIp) != string::npos){
        return true;
    }
}

// add current Relay to header history
string UdpRelay::msgRelayAdd(char *hdrMsg){

    struct sockaddr_in sa;

    // store this IP address in sa:
    inet_pton(AF_INET, groupIp.c_str(), &(sa.sin_addr));
    char temp [4];
    memcpy(temp, &(sa.sin_addr), 4);

    string hdrRelMsg;
    hdrRelMsg.append(msgHeaderGet(hdrMsg));

    hdrRelMsg.append(temp);
    hdrRelMsg.append(msgMessageGet(hdrMsg));

    // increment hops
    hdrRelMsg[3] = hdrRelMsg[3] + 1;

    return hdrRelMsg;

}


// get length of whole header+message string
int UdpRelay::msgGetLength(string hdrMsg){
    int length =  hdrMsg.size();
    if (length < 0){
        std::cerr << "msgGetLength - bad string" << endl;
        return -1;
    }
    return length;
}

// convert char[] to string
string UdpRelay::msgCharToString(char* chrArary){
    string str = (string)chrArary;
    return str;
}

// convert string to char[]
char* UdpRelay::msgStringToChar(string str){
    char *s2c =new char[str.size()+1];
    s2c[str.size()]=0;
    memcpy(s2c,str.c_str(),str.size());
    return s2c;
};

#pragma mark thread initialization methods

// non-static member function for execution of command thread work
void *UdpRelay::commandFunc() {
    std::string temp;
    bool live{true};
    while(live) {
        std::getline(std::cin, temp);
        if (temp == "help") {
            UdpHelp();
        } else if (temp.substr(0, 4) == "add ") {
            UdpAddRemIP(temp.substr(4, temp.size()));
        } else if (temp.substr(0, 7) == "delete ") {
            UdpDelRemIP(temp.substr(7, 15));
        } else if (temp == "show") {
            UdpShow();
        } else if (temp == "quit"){
            UdpQuit();
        }
    }
    pthread_exit(0);
}

/* acceptThread: creates a Socket object with a given TCP port, (namely the last
 * 5 digits of your student ID); and thereafter keeps accepting a TCP connection
 * request from a remote TdpRelay; checks if another TCP connection has already
 * been established to that remote node; if so, deletes the former connection;
 * and starts relayOutThread that keeps reading a UDP multicast message relayed
 * through this TCP connection from the remote node and multicasting it to the
 * local group (i.e., groupIp). */
void *UdpRelay::acceptFunc(){
    // creates a Socket object with a given TCP port
    masterSocket = new Socket(TCP_PORT);


    // keeps accepting a TCP connection...
    TcpServerSD = masterSocket->getServerSocket();
    if (TcpServerSD < NO_ERROR) {
        error("UdpAddRemIp: ERROR - failed getServerSocket");
    }


    // prep sockadder struct for receipt of connection name
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    socklen_t Slen = sizeof(sa);
    getpeername(TcpServerSD, (struct sockaddr *) &sa, &Slen);


    // get connection name - announce registration
    char peer[NI_MAXSERV];
    int res = getnameinfo((struct sockaddr *) &sa, sizeof(sa), peer,
                          sizeof(peer), NULL, 0, 0);
    if (res) {
        error("UdpAddRemIp: ERROR - failed getnameinfo");
    }
    int hostTrunc = strlen(peer) - 8;
    string hostStr = msgCharToString(peer);
    hostStr.resize(hostTrunc);


    // register peer as a connected client
    TCP_SSdToClient.insert(std::pair< int, string > ( TcpServerSD, hostStr ));
    cout << "UdpRelay: registered " << hostStr << endl;

    TCP_ClientToCSd.insert(std::pair< string, int > ( hostStr, TcpServerSD ));


    // if connection already in place, close former
    if (TCP_ServerToCSd.find(hostStr) != TCP_ServerToCSd.end()){
        close(TCP_ServerToCSd.find(hostStr)->second);
    }


    // spawn relayOutThread to keep reading UDP multicast message through TCP
    pthread_t relayOutThread;
    int errorID = pthread_create(&relayOutThread, NULL, call_relayOutFunc,
                                 this);
    if (errorID != NO_ERROR) {
        std::cerr << "failed to create relayOutThread..." << std::endl;
        exit(-1);
    }

    pthread_join(relayOutThread, NULL);
    TCP_ClientToCSd.erase(hostStr);
    TCP_CSdToServer.erase(TcpServerSD);
    pthread_exit(0);

}
/* relayInThread creates a UdpMulticast object with a given groupIp and
 * groupPort, and thereafter keeps catching a local UDP multicast message. Every
 * time relayInThread receives a UDP multicast message, it scans the multicast
 * header to examine if it includes the local UdpRelay's IP address.  If so, it
 * simply discards this message.  Otherwise relayInThread forwards this message
 * through TCP connections to all the remote network segments/groups. */
void *UdpRelay::relayInFunc(){
    char groupIpAddr[15];
    memcpy(groupIpAddr, msgStringToChar(groupIp), 15*sizeof(char));

    // creates a UdpMulticast object
    UdpMC = new UdpMulticast(groupIpAddr, stoi(groupPort));

    // keeps catching a UDP multicast message
    int servSkt = UdpMC->getServerSocket();


    while (live){
        //  UDP transmission received via recv()
        UdpMC->recv(bufferUdpInbound, BUFSIZ);

        // check for groupIp in header
        if (!msgRelayFind(bufferUdpInbound)) {
            // add groupIp to header
            string tempStr = bufferUdpInbound;

            if (tempStr.length() > 0){
                cout << "";
            }
            string msgHdrAdded = msgRelayAdd(bufferUdpInbound);

            // send to each TCP server that has been connected
            for (const auto &element: TCP_ClientSDs) {
                TcpSend(element, msgHdrAdded.c_str());
                cout << "UdpRelay: relay " <<
                msgMessageGet(msgHdrAdded.c_str()) << " to remoteGroup["
                     << TCP_CSdToServer.find(element)->second << ":"
                     << groupPort << "]" << endl;
            }
        }
    }
    pthread_exit(0);
}

/* relay out thread keeps reading a UDP multicast message relayed through this
 * TCP connection from the remote node; scans the multicast header to examine
 * if it includes the local UdpRelay's IP address; if so, simply discards this
 * message, otherweise multicasts it to the local group, (i.e., groupIp) */
void *UdpRelay::relayOutFunc() {
    // create UdpClientSocket (don't use SD)
    UdpClientSD =  UdpMC->getClientSocket();

    while (live) {
        // TCP Receive Message
        if (TcpReceive(TcpServerSD, bufferTCPInbound) == 0) {
            pthread_exit(0);
        };


        // validate first-see
        if(!msgRelayFind(bufferTCPInbound)){
            // broadcast via UDP
            int goodBroadcast = UdpMC->multicast(bufferTCPInbound);
            // announce broadcast
            if (goodBroadcast){
                cout << "UdpRelay: broadcast buf[" << strlen(bufferTCPInbound)
                     << "] to " << groupIp << ":" << groupPort << endl;
            }
        }
        else {
            cout << "seen this message before, not broadcasting..." << endl;
        }
        memset(bufferTCPInbound, 0, strlen(bufferTCPInbound));
    }
    pthread_exit(0);
}