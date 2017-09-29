#include "request.h"

#include <iostream>


Request::Request(Address addr, bool outgoing, QString message, RequestHandler *handler)
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
    addResponse(DummyRequest{m_addr, m_nonce, ""});

    if (m_outgoing)
    {
        m_timer = new QTimer(this);
        connect(m_timer, SIGNAL(timeout()), this, SLOT(timeout()));
        m_timer->start(3000);
    }
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
    if (getType() == "register" && m_args.size() == 3)
    {
        if (!m_handler->isConnected(m_addr))
        {
            m_handler->connectPeer(m_addr, m_args.at(1));
            m_response = m_handler->getFingerPrint() + ":" + m_handler->getKey(m_handler->getFingerPrint());
            //responses.append(new Request(m_addr, true, m_nonce + ":ack " + m_handler->getFingerPrint() + ":" + m_handler->getKey(m_handler->getFingerPrint()), m_handler));
        }
    }
    else if (getType() == "ping" && m_args.size() == 2)
    {
        std::cout << "pinging: " << m_args.at(1).toStdString() << std::endl;
        if (m_handler->hasLocalKey(m_args.at(1)))
            m_error = false;
            //responses.append(new Request(m_addr, true, m_nonce + ":ack", m_handler));
        else
        {
            Request *lookup = m_handler->findRequest(DummyRequest{Address{}, 0, m_args.at(1)});
            if (lookup != nullptr)
            {
                lookup->addResponse(DummyRequest{m_addr, m_nonce, ""});
                delete this;
                return;
            }
            else
            {
                QList<DummyRequest> callbacks;
                callbacks.append(DummyRequest{m_addr, m_nonce, ""});
                foreach (Address addr, m_handler->listPeers())
                {
                    m_count += 1;
                    m_handler->makeRequest(addr, true, "ping:" + m_args.at(1), callbacks);
                }
            }
            m_error = true;
        }
    }

    QString respMsg;
    if (m_error)
        respMsg = ":dck " + m_response;
    else
        respMsg = ":ack " + m_response;
    for (int i = 0; i < m_responses.size(); ++i)
    {
        DummyRequest dumbResp = m_responses.at(i);
        Request *response = new Request(dumbResp.addr, true, dumbResp.nonce + respMsg, m_handler);
        response->process();
    }

    for (int i = 0; i < m_callbacks.size(); ++i)
    {
        Request *callback = m_handler->findRequest(m_callbacks[i]);
        if (callback != nullptr)
            QMetaObject::invokeMethod(callback, "process", Qt::QueuedConnection);
    }

    m_handler->removeRequest(this);
}

void Request::timeout()
{
    std::cout << "timeout" << std::endl;
    m_handler->removeRequest(this);
    delete this;
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

bool Request::looksUp(QString lookup)
{
    return m_args.at(0) == "ping" && m_args.at(1) == lookup;
}

DummyRequest Request::toDummy()
{
    return DummyRequest{m_addr, m_nonce, ""};
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
        makeRequest(addr, true, "register " + getFingerPrint() + ":" + getKey(getFingerPrint()), QList<DummyRequest>());
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
    if (dumbReq.lookup != "")
    {
        for (int i = 0; i < m_requests.size(); ++i)
        {
            if (m_requests.at(i)->looksUp(dumbReq.lookup))
                return m_requests.at(i);
        }
    }
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

void RequestHandler::makeRequest(Address addr, bool outgoing, QString message, QList<DummyRequest> callbacks)
{
    Request *request;
    if (outgoing)
        request = new Request(addr, outgoing, getNonce(addr) + ":" + message, this);
    else
        request = new Request(addr, outgoing, message, this);
    foreach (DummyRequest callback, callbacks)
    {
        request->addCallback(callback);
    }
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

