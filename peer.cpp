#include "peer.h"

#include <QtCore/QFile>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include <QtCore/QStandardPaths>
#include <iostream>

Peers::Peers()
{
    read();
}

Peers::~Peers()
{
    std::cout << "closing" << std::endl;
    write();
}

Peer Peers::get(Address addr, QString fingerPrint)
{
    if (m_peers.contains(addr))
    {
        if (fingerPrint != "" && m_peers[addr].fingerPrint != fingerPrint)
            throw PeerException();
        return m_peers[addr];
    }
    throw PeerException();
}

void Peers::add(Peer peer)
{
    m_peers[peer.addr] = peer;
    write();
}

bool Peers::isConnected(Address addr)
{
    return m_peers[addr].connected;
}

void Peers::setConnected(Address addr, bool connected)
{
    m_peers[addr].connected = connected;
}

void Peers::read()
{
    QFile file(QStandardPaths::writableLocation(QStandardPaths::DataLocation) + "/peers.json");
    // no file, just assume the array is empty
    if (!file.open(QIODevice::ReadOnly))
        return;
    QByteArray data = file.readAll();
    QJsonObject json = QJsonDocument::fromJson(data).object();
    QJsonArray peerArray = json["peers"].toArray();
    for (int i = 0; i < peerArray.size(); ++i)
    {
        QJsonObject peer = peerArray[i].toObject();
        std::cout << "Got Peer: " << peer["host"].toString().toStdString() << std::endl;
        Address addr = {QHostAddress(peer["host"].toString()), peer["port"].toString().toUShort()};
        m_peers[addr] = (Peer{addr, peer["fingerPrint"].toString(), peer["nonce"].toString().toUShort()});
    }
}

void Peers::write()
{
    QJsonObject json;
    QJsonArray peerArray;
    QList<Peer> peers = m_peers.values();
    for (int i = 0; i < peers.size(); ++i)
    {
        QJsonObject peer;
        peer["host"] = peers.at(i).addr.host.toString();
        peer["port"] = peers.at(i).addr.port;
        peer["fingerPrint"] = peers.at(i).fingerPrint;
        peer["nonce"] = peers.at(i).nonce;
        peerArray.append(peer);
    }
    json["peers"] = peerArray;
    QJsonDocument doc(json);
    QFile file(QStandardPaths::writableLocation(QStandardPaths::DataLocation) + "/peers.json");
    if (!file.open(QIODevice::WriteOnly))
    {
        std::cout << "Failed to write peers" << std::endl;
        return;
    }
    file.write(doc.toJson());
    file.close();
}

