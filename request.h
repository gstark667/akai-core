#ifndef H_REQUEST
#define H_REQUEST

#include <QtCore/QTextCodec>
#include <QtCore/QSettings>
#include <QtCore/QList>
#include <QtCore/QMap>
#include <QtCore/QPair>
#include <QtCore/QMetaObject>
#include <QtNetwork/QUdpSocket>


class RequestHandler;

class Request: public QObject
{
    Q_OBJECT
private:
    QStringList m_args;
    RequestHandler *m_handler;
    QHostAddress m_addr;
    quint16 m_port;
    bool m_outgoing;
    quint16 m_nonce;

public:
    Request(QHostAddress addr, quint16 port, bool outgoing, QString message, RequestHandler *handler);
    bool isAcknowledge();
    QString getType();
    QString getMessage();

    QHostAddress getAddr() { return m_addr; };
    quint16 getPort() { return m_port; };
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
    QMap<QPair<QString, quint16>, quint16> m_nonce;

public:
    RequestHandler(QObject *parent);
    quint16 getNonce(QHostAddress addr, quint16 port);

private slots:
    void readDatagrams();

public slots:
    Request *findRequest(QHostAddress addr, quint16 port, quint16 nonce);
    void sendRequest(Request *request);
    void makeRequest(QHostAddress addr, quint16 port, bool outgoing, QString message);
    void addRequest(Request *request);
    void removeRequest(Request *request);
};

#endif
