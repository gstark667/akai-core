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
    for (size_t i = 0; i < m_args.size(); ++i)
        std::cout << m_args.at(i).toStdString() << std::endl;
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
    if (getType().compare("register") == 0 && m_args.size() == 2)
    {
        responses.append(new Request(m_addr, true, QString::number(m_nonce) + ":ack", m_handler));
        std::cout << m_args.at(1).toStdString() << std::endl;
    }
    else if (getType().compare("key") == 0 && m_args.size() == 3)
    {
        std::cout << "importing key: " << m_args.at(1).toStdString() << ": " << m_args.at(2).toStdString() << std::endl;
    }

    for (size_t i = 0; i < responses.size(); ++i)
    {
        responses.at(i)->process();
    }
    m_handler->removeRequest(this);
}

QString Request::getMessage()
{
    QString message("");
    message += QString::number(m_nonce) + ":";
    if (m_args.size() == 1)
        return message + m_args.at(0);
    for (size_t i = 0; i < m_args.size() - 1; ++i)
        message += m_args.at(i) + " ";
    return message + ":" + m_args.at(m_args.size() - 1);
}

DummyRequest Request::toDummy()
{
    return DummyRequest{m_addr, m_nonce, false};
}


RequestHandler::RequestHandler(QObject *parent): QObject(parent)
{
    m_crypto = new Crypto(m_settings.value("key").toString());
    //QString test = m_crypto->sign("test");
    //std::cout << test.toStdString() << std::endl;
    QString test2 = m_crypto->encrypt("422F410CE93D7EC4005C46918B5D67B61AC9A727", "test");
    std::cout << test2.toStdString() << std::endl;
    QString sender, text;
    text = m_crypto->decrypt(sender, test2);
    std::cout << text.toStdString() << std::endl;

    if (!m_settings.contains("port"))
        m_settings.setValue("port", 6667);
    m_sock.bind(QHostAddress("127.0.0.1"), quint16(m_settings.value("port").toUInt()));
    connect(&m_sock, &QUdpSocket::readyRead, this, &RequestHandler::readDatagrams);
    makeRequest(Address{QHostAddress("127.0.0.1"), 6666}, true, "register");
}

RequestHandler::~RequestHandler()
{
    delete m_crypto;
}

quint16 RequestHandler::getNonce(Address addr)
{
    if (!m_nonce.contains(addr))
        m_nonce[addr] = 0;
    return m_nonce[addr]++;
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
        QString message = QString(datagram.data());
        Request *request = new Request(Address{senderAddr, senderPort}, false, message, this);
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
    for (size_t i = 0; i < m_requests.size(); ++i)
    {
        Request *request = m_requests.at(i);
        if (dumbReq.addr == request->getAddress() && dumbReq.nonce == request->getNonce())
            return request;
    }
    return nullptr;
}

void RequestHandler::sendRequest(Request *request)
{
    std::cout << "sending request: " << request->getMessage().toStdString() << std::endl;
    m_sock.writeDatagram(request->getMessage().toUtf8(), request->getAddress().host, request->getAddress().port);
}

void RequestHandler::makeRequest(Address addr, bool outgoing, QString message)
{
    Request *request;
    if (outgoing)
        request = new Request(addr, outgoing, this->getNonce(addr) + ":" + message, this);
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

