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

private:
    void read();
    void write();
};

#endif
