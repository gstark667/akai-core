#ifndef H_REQUEST
#define H_REQUEST

#include <QtCore/QTextCodec>
#include <QtCore/QSettings>
#include <QtCore/QList>
#include <QtCore/QMap>
#include <QtCore/QPair>
#include <QtCore/QMetaObject>
#include <QtNetwork/QUdpSocket>

#include "address.h"

class RequestHandler;

class Request: public QObject
{
    Q_OBJECT
private:
    QStringList m_args;
    RequestHandler *m_handler;
    Address m_addr;
    bool m_outgoing;
    quint16 m_nonce;

public:
    Request(Address addr, bool outgoing, QString message, RequestHandler *handler);
    bool isAcknowledge();
    QString getType();
    QString getMessage();

    Address getAddress() { return m_addr; };
    bool isOutgoing() { return m_outgoing; };
    quint16 getNonce() { return m_nonce; };

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
    QMap<Address, quint16> m_nonce;

public:
    RequestHandler(QObject *parent);
    quint16 getNonce(Address addr);

private slots:
    void readDatagrams();

public slots:
    Request *findRequest(Address addr, quint16 nonce);
    void sendRequest(Request *request);
    void makeRequest(Address addr, bool outgoing, QString message);
    void addRequest(Request *request);
    void removeRequest(Request *request);
};

#endif
