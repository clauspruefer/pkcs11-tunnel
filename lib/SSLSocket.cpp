#include <errno.h>

#include "SSLSocket.hpp"


using namespace std;

SSLSocket::SSLSocket(const string Address, const uint16_t ListenPort) :
    Socket(Address, ListenPort),
    CloseConnection(false),
    ChunkEndReached(false),
    PrivkeyPointer(NULL),
    Handshake(new SSLHandshake())

{
    DBG(200, "SSLSocket Constructor called.");

    //- reset receive buffer
    resetRecvBuffer();

    //- init send timeout
    TimeoutSendObj.setTimeoutBlocking(false);
    TimeoutSendObj.setTimeout(SSL_SOCKET_SEND_TIMEOUT_SEC, 0);

}

SSLSocket::~SSLSocket()
{
    DBG(200, "SSLSocket Destructor called.");
    delete Handshake;
}

void SSLSocket::setupSSLEngine()
{

    const string EngineID = "dynamic";

    ENGINE_load_builtin_engines();

    PKCS11Engine = ENGINE_by_id(EngineID.c_str());

    //- if engine is not available, exit
    if (!PKCS11Engine) {
        cout << "Error setting up Openssl pkcs11 Engine!" << endl;
        exit(EXIT_FAILURE);
    }

    string EngineLib(OPENSSL_OPENSC_ENGINE_PKCS11_LIBRARY);
    string OpenSCLib(OPENSC_ENGINE_PKCS11_LIBRARY);

    ENGINE_ctrl_cmd_string(PKCS11Engine, "SO_PATH", EngineLib.c_str(), 0);
    ENGINE_ctrl_cmd_string(PKCS11Engine, "ID", "pkcs11", 0);
    ENGINE_ctrl_cmd_string(PKCS11Engine, "LIST_ADD", "1", 0);
    ENGINE_ctrl_cmd_string(PKCS11Engine, "LOAD", NULL, 0);
    ENGINE_ctrl_cmd_string(PKCS11Engine, "MODULE_PATH", OpenSCLib.c_str(), 0);

    DBG(40, "OpenSSL Engine Library:" << EngineLib);
    DBG(40, "OpenSC PKCS Library:" << OpenSCLib);

    int rc = ENGINE_init(PKCS11Engine);
    DBG(100, "Engine init result:" << rc);

    const char* LoadedEngineID = ENGINE_get_id(PKCS11Engine);
    DBG(100, "Loaded engine with id:" << LoadedEngineID);

    ENGINE_set_default(PKCS11Engine, ENGINE_METHOD_RSA | ENGINE_METHOD_EC);

    const char *Prompt = "Enter User PIN:";

    string UserPin(getpass(Prompt));

    if (UserPin.length() > 20) { exit(EXIT_FAILURE); }

    string ObjLocation;
    ObjLocation.append(Config::CardSlot);
    ObjLocation.append(string(":"));
    ObjLocation.append(Config::ContainerId);

    ENGINE_ctrl_cmd_string(PKCS11Engine, "PIN", UserPin.c_str(), 0);
    PrivkeyPointer = ENGINE_load_private_key(PKCS11Engine, ObjLocation.c_str(), NULL, NULL);

    UserPin.clear();

}

void SSLSocket::setupSSL()
{

    DBG(10, "SSLSocket::setupSSL() called.");

    //- setup ssl engine if no key file given
    if (Config::KeyFile.length() == 0) {
        setupSSLEngine();
    }

    //- setup client SSL context
    if (Config::Type == "client") {
        SSLContext = SSL_CTX_new(TLS_client_method());
        if (SSLContext == NULL) {
            cout << "SSL client context creation error." << endl;
            exit(EXIT_FAILURE);
        }
        SSL_CTX_set_min_proto_version(SSLContext, TLS1_2_VERSION);
    }

    //- setup server SSL context
    if (Config::Type == "server") {

        //- set server method
        SSLContext = SSL_CTX_new(TLS_server_method());
        if (SSLContext == NULL) {
            cout << "SSL server context creation error." << endl;
            exit(EXIT_FAILURE);
        }
        SSL_CTX_set_min_proto_version(SSLContext, TLS1_2_VERSION);

        //- enable client cert verification
        SSL_CTX_set_verify(SSLContext, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    }

    //- add ciphers
    int Ciphers = SSL_CTX_set_cipher_list(SSLContext, "HIGH");
    DBG(100, "SSL setup ciphers rc:" << Ciphers);

    //- disable compression
    SSL_CTX_set_options(SSLContext, SSL_OP_NO_COMPRESSION);

    //- disable ssl tickets
    SSL_CTX_set_options(SSLContext, SSL_OP_NO_TICKET);

    //- disable dtls
    SSL_CTX_set_options(SSLContext, SSL_OP_NO_DTLSv1);
    SSL_CTX_set_options(SSLContext, SSL_OP_NO_DTLSv1_2);

    //- set quite shutdown
    SSL_CTX_set_quiet_shutdown(SSLContext, 1);

    if (Config::Type == "server") {

        //- load CA cert
        if (SSL_CTX_load_verify_locations(SSLContext, Config::CACertFile.c_str(), NULL) <= 0) {
            cout << "SSL load verify locations error." << endl;
            exit(EXIT_FAILURE);
        }

        SSL_CTX_set_client_CA_list(SSLContext, SSL_load_client_CA_file(Config::CACertFile.c_str()));

    }

    //- load cert
    if (SSL_CTX_use_certificate_file(SSLContext, Config::CertFile.c_str(), SSL_FILETYPE_PEM) <=0) {
        cout << "SSL load cert file error." << endl;
        exit(EXIT_FAILURE);
    }

    //- load private key file
    if (Config::KeyFile.length() > 0 && SSL_CTX_use_PrivateKey_file(SSLContext, Config::KeyFile.c_str(), SSL_FILETYPE_PEM) <=0) {
        cout << "SSL load private key file error." << endl;
        exit(EXIT_FAILURE);
    }

    if (Config::KeyFile.length() == 0 && PrivkeyPointer == NULL) {
        cout << "No key file configuration found and no valid key from smartcard." << endl;
        exit(EXIT_FAILURE);
    }

    //- use private key (pointer) from pkcs11 engine
    if (Config::KeyFile.length() == 0 && SSL_CTX_use_PrivateKey(SSLContext, PrivkeyPointer) <= 0) {
        cout << "SSL load smartcard private key error." << endl;
        exit(EXIT_FAILURE);
    }

}

void SSLSocket::ProxyHandshake(string ClientID) {

    stringstream SendData;

    SendData << ClientID << string(PROXY_CMD_NEW_CONNECTION);

    if (sendDataChunk(SendData.str()) == false) {
        DBG(10, "Proxy handshake send failed.");
        exit(EXIT_FAILURE);
    }

}

bool SSLSocket::sendDataChunk(const string Data)
{

    string SendData;

    SendData.append(string(PAYLOAD_MARKER_PREFIX));
    SendData.append(Data);
    SendData.append(string(PAYLOAD_MARKER_POSTFIX));

    //- reset send timeout
    TimeoutSendObj.reset();

    while (true) {

        int SendBytes = SSL_write(SSLConnection, SendData.c_str(), SendData.length());
        int SendResult = SSL_get_error(SSLConnection, SendBytes);

        DBG(200, "Bytes:" << SendBytes << " ResultCode:" << SendResult << " ResultError:" << strerror(SendResult));

        //- on success break
        if (SendResult == 0) { break; }

        //- on error sleep
        else {
            this_thread::sleep_for(chrono::milliseconds(ERROR_SLEEP_INTERVAL_MSEC));
        }

        //- check timeout reached
        if (TimeoutSendObj.checkTimeoutReached() == true) {
            return false;
        }

    }

    return true;
}

void SSLSocket::recvDataChunk()
{

    CloseConnection = false;

    int RecvBytes = -1;
    RecvBytes = SSL_read(SSLConnection, RecvBuffer, TMP_BUFFER_SIZE);

    if (RecvBytes == 0) {
        DBG(10, "SSL connection close initiated.");
        CloseConnection = true;
        return;
    }

    int result = SSL_get_error(SSLConnection, RecvBytes);

    if (result == SSL_ERROR_WANT_READ) {
        DBG(200, "SSL error want read.");
        return;
    }

    if (result == SSL_ERROR_SYSCALL || result == SSL_ERROR_SSL) {
        DBG(120, "SSLSocket.recvDataChunk() SSL_ERROR_SYSCALL or SSL_ERROR_SSL error:" << strerror(errno));
        this_thread::sleep_for(chrono::milliseconds(ERROR_SLEEP_INTERVAL_MSEC));
    }

    if (RecvBytes > 0) {
        DBG(200, "recvDataChunkSSL() RecvBytes:" << RecvBytes);

        Received.append(RecvBuffer, RecvBytes);

        string CompareStart(PAYLOAD_MARKER_PREFIX);
        string CompareEnd(PAYLOAD_MARKER_POSTFIX);

        if (Received.compare(0, CompareStart.size(), CompareStart) == 0 && Received.compare(Received.size()-CompareEnd.size(), CompareEnd.size(), CompareEnd) == 0) {
            Received.replace(Received.begin(), Received.begin()+CompareStart.size(), "");
            Received.replace(Received.end()-CompareEnd.size(), Received.end(), "");
            ChunkEndReached = true;
            resetRecvBuffer();
        }

    }

}

void SSLSocket::doClientHandshake()
{

    //- setup new ssl connection
    SSLConnection = SSL_new(SSLContext);
    SSL_set_fd(SSLConnection, SocketFD);

    //- reset handshake status/counter
    Handshake->reset();

    //- try connect
    if (!Handshake->connectLoop(SSLConnection)) {
        cout << "Client SSL connect failed." << endl;
        exit(EXIT_FAILURE);
    }

    //- try handshake
    if (!Handshake->HandshakeLoop(SSLConnection)) {
        cout << "Client SSL handshake failed." << endl;
        exit(EXIT_FAILURE);
    }

}

void SSLSocket::doServerHandshakeLoop()
{
    //- setup new ssl connection
    SSLConnection = SSL_new(SSLContext);
    SSL_set_fd(SSLConnection, ServerAcceptedFD);

    while (true) {
        if (doServerHandshake()) { break; }
    }

}

bool SSLSocket::doServerHandshake()
{

    //- reset handshake status/counter
    Handshake->reset();

    //- try accept
    if (!Handshake->acceptLoop(SSLConnection)) {
        return false;
    }

    //- try handshake
    if (!Handshake->HandshakeLoop(SSLConnection)) {
        return false;
    }

    return true;
}

void SSLSocket::renegotiate()
{

    //- reset handshake status/counter
    Handshake->reset();

    //- try renegotiate
    if (!Handshake->renegotiateLoop(SSLConnection)) {
        cout << "Client SSL renegotiate failed." << endl;
        exit(EXIT_FAILURE);
    }

}

void SSLSocket::resetRecvBuffer()
{
    memset(RecvBuffer, 0, TMP_BUFFER_SIZE);
}

void SSLSocket::lock()
{
    SendLock.lock();
}

void SSLSocket::unlock()
{
    SendLock.unlock();
}

void SSLSocket::free()
{
    SSL_free(SSLConnection);
}

void SSLSocket::shutdown()
{
    Handshake->shutdown(SSLConnection);
}
