#ifndef H_REQUEST
#define H_REQUEST

#include <QtCore/QTextCodec>
#include <QtCore/QSettings>
#include <QtCore/QList>
#include <QtCore/QMap>
#include <QtCore/QPair>
#include <QtCore/QMetaObject>
#include <QtCore/QTimer>
#include <QtNetwork/QUdpSocket>
#include <gpgme.h>
#include <vector>

#include "address.h"
#include "crypto.h"
#include "peer.h"

class RequestHandler;

typedef struct
{
    Address addr;
    quint16 nonce;
    QString lookup;
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
    QTimer *m_timer = nullptr;
    int m_count = -1;
    bool m_error = false;
    QString m_response = "";
    std::vector<DummyRequest> m_callbacks;
    std::vector<DummyRequest> m_responses;

public:
    Request(Address addr, bool outgoing, QString message, RequestHandler *handler);
    bool isAcknowledge();
    QString getType();
    QString getMessage();
    QString getArg(int index) { return m_args.at(index); };
    int countArgs() { return m_args.size(); };
    bool looksUp(QString lookup);

    Address getAddress() { return m_addr; };
    bool isOutgoing() { return m_outgoing; };
    quint16 getNonce() { return m_nonce; };

    DummyRequest toDummy();

public slots:
    void acknowledge(Request *response);
    void process();
    void timeout();
    void addCallback(DummyRequest callback) { m_callbacks.push_back(callback); };
    void addResponse(DummyRequest response) { m_responses.push_back(response); };
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
    void makeRequest(Address addr, bool outgoing, QString message, QList<DummyRequest> callbacks);
    void addRequest(Request *request);
    void removeRequest(Request *request);

    void connectPeer(Address addr, QString fingerPrint);
};

#endif
