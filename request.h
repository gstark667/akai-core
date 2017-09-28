#ifndef H_REQUEST
#define H_REQUEST

#include <QtCore/QTextCodec>
#include <QtCore/QSettings>
#include <QtCore/QList>
#include <QtCore/QMap>
#include <QtCore/QPair>
#include <QtCore/QMetaObject>
#include <QtNetwork/QUdpSocket>
#include <gpgme.h>

#include "address.h"
#include "crypto.h"
#include "peer.h"

class RequestHandler;

typedef struct
{
    Address addr;
    quint16 nonce;
    bool isEmpty;
} DummyRequest;

class RequestException: public QException {};
class MessageException: public QException {};

class Request: public QObject
{
    Q_OBJECT
private:
    QStringList m_args;
    RequestHandler *m_handler;
    Address m_addr;
    bool m_outgoing;
    quint16 m_nonce;
    DummyRequest m_callback;
    bool m_error = false;

public:
    Request(Address addr, bool outgoing, QString message, RequestHandler *handler, DummyRequest callback=DummyRequest{});
    bool isAcknowledge();
    QString getType();
    QString getMessage();
    QString getArg(int index) { return m_args.at(index); };
    int countArgs() { return m_args.size(); };

    Address getAddress() { return m_addr; };
    bool isOutgoing() { return m_outgoing; };
    quint16 getNonce() { return m_nonce; };

    DummyRequest toDummy();

public slots:
    void acknowledge(Request *response);
    void process();
};

class RequestHandler: public QObject
{
    Q_OBJECT
private:
    QSettings m_settings;
    QUdpSocket m_sock;
    QList<Request*> m_requests;
    QStringList m_localKeys;
    Peers *m_peers;
    Crypto *m_crypto;

public:
    RequestHandler(QObject *parent);
    ~RequestHandler();
    void addPeer(Address addr, QString fingerPrint);
    QList<Address> listPeers() { return m_peers->list(); };
    quint16 getNonce(Address addr) { return m_peers->getNonce(addr); };
    void removePeer(Address addr);

    QString getKey(QString fingerPrint) { return m_crypto->getKey(fingerPrint); };
    void addKey(QString fingerPrint, QString text) { m_crypto->addKey(fingerPrint, text); };

    QString getFingerPrint();
    QString getFingerPrint(Address addr);
    bool isConnected(Address addr);
    QString encrypt(QString message, Address addr);
    QString decrypt(QString message, Address addr);

    void addLocalKey(QString fingerPrint) { m_localKeys.append(fingerPrint); };
    bool hasLocalKey(QString fingerPrint) { return m_localKeys.contains(fingerPrint); };

private slots:
    void readDatagrams();

public slots:
    Request *findRequest(DummyRequest dumbReq);
    void sendRequest(Request *request);
    void makeRequest(Address addr, bool outgoing, QString message);
    void addRequest(Request *request);
    void removeRequest(Request *request);

    void connectPeer(Address addr, QString fingerPrint);
};

#endif
