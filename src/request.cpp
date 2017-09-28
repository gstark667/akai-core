#include "request.h"

#include <iostream>


Request::Request(Address addr, bool outgoing, QString message, RequestHandler *handler, DummyRequest callback)
{
    QString nonce = message.section(":", 0, 0);
    QString front = message.section(':', 1, 1);
    QString back = message.section(':', 2);
    m_addr = addr;
    m_outgoing = outgoing;
    m_nonce = nonce.toUInt();
    m_args = front.trimmed().split(" ");
    if (!back.isNull())
        m_args.append(back);
    m_handler = handler;
    m_callback = callback;
}

bool Request::isAcknowledge()
{
    return m_args.at(0).compare("ack") == 0;
}

QString Request::getType()
{
    return m_args.at(0);
}

void Request::acknowledge(Request *response)
{
    std::cout << "got the ack" << std::endl;
    if (getType() == "register" && response->countArgs() == 3)
    {
        m_handler->connectPeer(m_addr, response->getArg(1));
        m_handler->addKey(response->getArg(1), response->getArg(2));
    }
    m_handler->removeRequest(this);
}

void Request::process()
{
    if (m_outgoing)
    {
        m_handler->sendRequest(this);
        return;
    }

    std::cout << "processing" << std::endl;
    QList<Request*> responses;
    if (getType() == "register" && m_args.size() == 3)
    {
        if (!m_handler->isConnected(m_addr))
        {
            m_handler->connectPeer(m_addr, m_args.at(1));
            responses.append(new Request(m_addr, true, m_nonce + ":ack " + m_handler->getFingerPrint() + ":" + m_handler->getKey(m_handler->getFingerPrint()), m_handler));
        }
    }
    else if (getType() == "ping" && m_args.size() == 2)
    {
        std::cout << "pinging: " << m_args.at(1).toStdString() << std::endl;
        if (m_handler->hasLocalKey(m_args.at(1)))
            responses.append(new Request(m_addr, true, m_nonce + ":ack", m_handler));
        else
        {
            responses.append(new Request(m_addr, true, m_nonce + ":dck", m_handler));
            /*foreach (Address addr, m_peers->list())
            {
                responses.append(new Request(m_addr, true, m_nonce + ":ping", m_handler));
                std::cout << "asking for ping: " << addr.host.toStdString() << std::endl;
            }*/
        }
    }

    for (int i = 0; i < responses.size(); ++i)
    {
        responses.at(i)->process();
    }

    Request *callback = m_handler->findRequest(m_callback);
    if (callback != nullptr)
        QMetaObject::invokeMethod(callback, "process", Qt::QueuedConnection);
        
    m_handler->removeRequest(this);
}

QString Request::getMessage()
{
    QString message("");
    message += QString::number(m_nonce) + ":";
    if (m_args.size() == 1)
        return message + m_args.at(0);
    for (int i = 0; i < m_args.size() - 1; ++i)
        message += m_args.at(i) + " ";
    message = message.trimmed();
    return message + ":" + m_args.at(m_args.size() - 1);
}

DummyRequest Request::toDummy()
{
    return DummyRequest{m_addr, m_nonce, false};
}


RequestHandler::RequestHandler(QObject *parent): QObject(parent)
{
    m_peers = new Peers();
    m_crypto = new Crypto(m_settings.value("key").toString());
    m_settings.setValue("key", m_crypto->getFingerPrint());

    if (!m_settings.contains("port"))
        m_settings.setValue("port", 6667);
    m_sock.bind(QHostAddress("127.0.0.1"), quint16(m_settings.value("port").toUInt()));
    connect(&m_sock, &QUdpSocket::readyRead, this, &RequestHandler::readDatagrams);

    std::cout << m_settings.value("port").toString().toStdString() << std::endl;
    foreach (Address addr, m_peers->list())
    {
        makeRequest(addr, true, "register " + getFingerPrint() + ":" + getKey(getFingerPrint()));
        std::cout << "Key: " << m_crypto->getKey(m_peers->get(addr).fingerPrint).toStdString() << std::endl;
    }
}

RequestHandler::~RequestHandler()
{
    delete m_peers;
    delete m_crypto;
}

QString RequestHandler::getFingerPrint()
{
    return m_crypto->getFingerPrint();
}

bool RequestHandler::isConnected(Address addr)
{
    return m_peers->isConnected(addr);
}

QString RequestHandler::encrypt(QString message, Address addr)
{
    Peer peer = m_peers->get(addr);
    return m_crypto->encrypt(message, peer.fingerPrint);
}

QString RequestHandler::decrypt(QString message, Address addr)
{
    Peer peer;
    QString text;
    std::cout << "Decrypting: " << message.toStdString() << std::endl;
    QString fingerPrint;
    try
    {
        text = m_crypto->decrypt(fingerPrint, message);
    }
    catch (RequestException e)
    {
        std::cout << "New fingerprint" << std::endl;
    }
    return text;
}

void RequestHandler::readDatagrams()
{
    QByteArray datagram;
    QHostAddress senderAddr;
    quint16 senderPort;
    while (m_sock.hasPendingDatagrams())
    {
        datagram.resize(m_sock.pendingDatagramSize());
        m_sock.readDatagram(datagram.data(), datagram.size(), &senderAddr, &senderPort);
        Address addr = {senderAddr, senderPort};
        QString message = QString(datagram.data());
        std::cout << "got message: " << message.toStdString() << ": from: " << senderPort << std::endl;
        if (message.indexOf("0:") != 0)
            message = decrypt(message, addr);
        Request *request = new Request(addr, false, message, this);
        if (request->isAcknowledge())
        {
            Request *request2 = findRequest(request->toDummy());
            if (request2 != nullptr)
                request2->acknowledge(request);
            std::cout << "got ack" << std::endl;
            delete request;
        }
        else
        {
            this->addRequest(request);
            QMetaObject::invokeMethod(request, "process", Qt::QueuedConnection);
        }
    }
}

Request *RequestHandler::findRequest(DummyRequest dumbReq)
{
    for (int i = 0; i < m_requests.size(); ++i)
    {
        Request *request = m_requests.at(i);
        if (dumbReq.addr == request->getAddress() && dumbReq.nonce == m_peers->get(request->getAddress()).nonce)
            return request;
    }
    return nullptr;
}

void RequestHandler::sendRequest(Request *request)
{
    QString message = request->getMessage();
    Address address = request->getAddress();
    bool connected = m_peers->isConnected(address);
    bool isRegister = message.indexOf("0:") == 0;
    std::cout << "sending message: " << message.toStdString() << ": to: " << address.port  << std::endl;
    if (!isRegister && connected)
        message = m_crypto->encrypt(m_peers->get(request->getAddress()).fingerPrint, message);
    if (connected || isRegister)
        m_sock.writeDatagram(message.toUtf8(), address.host, address.port);
    else
        throw RequestException();
}

void RequestHandler::makeRequest(Address addr, bool outgoing, QString message)
{
    Request *request;
    if (outgoing)
        request = new Request(addr, outgoing, getNonce(addr) + ":" + message, this);
    else
        request = new Request(addr, outgoing, message, this);
    QMetaObject::invokeMethod(request, "process", Qt::QueuedConnection);
    this->addRequest(request);
}

void RequestHandler::addRequest(Request *request)
{
    m_requests.append(request);
}

void RequestHandler::removeRequest(Request *request)
{
    m_requests.removeAll(request);
}

void RequestHandler::connectPeer(Address addr, QString fingerPrint)
{
    std::cout << "connecting peer: " << fingerPrint.toStdString() << std::endl;
    m_peers->add(Peer{addr, fingerPrint, 0, false});
    m_peers->setConnected(addr, true);
}

