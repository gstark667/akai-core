#ifndef H_PEER
#define H_PEER

#include <QtCore/QMap>
#include <QtCore/QException>
#include "address.h"

class PeerException: public QException {};

struct Peer
{
    Address addr;
    QString fingerPrint;
    quint16 nonce;
    bool connected = false;
};

class Peers
{
private:
    QMap<Address, Peer> m_peers;

public:
    Peers();
    ~Peers();

    QList<Address> list() { return m_peers.keys(); };
    Peer get(Address addr, QString fingerPrint="");
    void add(Peer peer);
    bool isConnected(Address addr);
    void setConnected(Address addr, bool connected);
    quint16 getNonce(Address addr);

private:
    void read();
    void write();
};

#endif
