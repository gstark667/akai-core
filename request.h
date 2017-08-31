#ifndef H_REQUEST
#define H_REQUEST

#include <QtCore/QTextCodec>
#include <QtCore/QSettings>
#include <QtCore/QList>
#include <QtCore/QMap>
#include <QtCore/QPair>
#include <QtCore/QMetaObject>
#include <QtNetwork/QUdpSocket>
#include <QtCrypto/QtCrypto>
#include <gpgme.h>

#include "address.h"
#include "crypto.h"
#include "peer.h"

class RequestHandler;

struct DummyRequest
{
    Address addr;
    quint16 nonce;
    bool isEmpty = true;
};

class RequestException: public QException
{
};

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

public:
    Request(Address addr, bool outgoing, QString message, RequestHandler *handler, DummyRequest callback=DummyRequest{});
    bool isAcknowledge();
    QString getType();
    QString getMessage();

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
    Peers *m_peers;
    Crypto *m_crypto;

public:
    RequestHandler(QObject *parent);
    ~RequestHandler();
    void addPeer(Address addr, QString fingerPrint);
    void removePeer(Address addr);

    QString encrypt(QString message, Address addr);
    QString decrypt(QString message, Address addr);

private slots:
    void readDatagrams();

public slots:
    Request *findRequest(DummyRequest dumbReq);
    void sendRequest(Request *request);
    void makeRequest(Address addr, bool outgoing, QString message);
    void addRequest(Request *request);
    void removeRequest(Request *request);
};

#endif
