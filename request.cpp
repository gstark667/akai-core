#include "request.h"

#include <iostream>

Request::Request(QHostAddress addr, quint16 port, bool outgoing, QString message, RequestHandler *handler)
{
    QString nonce = message.section(":", 0, 0);
    QString front = message.section(':', 1, 1);
    QString back = message.section(':', 2);
    m_addr = addr;
    m_port = port;
    m_outgoing = outgoing;
    m_nonce = nonce.toUInt();
    m_args = front.trimmed().split(" ");
    if (!back.isNull())
        m_args.append(back);
    for (size_t i = 0; i < m_args.size(); ++i)
        std::cout << m_args.at(i).toStdString() << std::endl;
    m_handler = handler;
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
    if (this->getType().compare("register") == 0)
    {
        responses.append(new Request(m_addr, m_port, true, QString::number(m_nonce) + ":ack", m_handler));
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

RequestHandler::RequestHandler(QObject *parent): QObject(parent)
{
    if (!m_settings.contains("port"))
        m_settings.setValue("port", 6667);
    m_sock.bind(QHostAddress("127.0.0.1"), quint16(m_settings.value("port").toUInt()));
    connect(&m_sock, &QUdpSocket::readyRead, this, &RequestHandler::readDatagrams);
    makeRequest(QHostAddress("127.0.0.1"), 6666, true, "register");
}

quint16 RequestHandler::getNonce(QHostAddress addr, quint16 port)
{
    QPair<QString, quint16> pair(addr.toString(), port);
    if (!m_nonce.contains(pair))
        m_nonce[pair] = 0;
    return m_nonce[pair]++;
}

void RequestHandler::readDatagrams()
{
    QByteArray datagram;
    QHostAddress sender;
    quint16 senderPort;
    while (m_sock.hasPendingDatagrams())
    {
	    datagram.resize(m_sock.pendingDatagramSize());
	    m_sock.readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);
        QString message = QString(datagram.data());
        Request *request = new Request(sender, senderPort, false, message, this);
        if (request->isAcknowledge())
        {
            Request *request2 = findRequest(request->getAddr(), request->getPort(), request->getNonce());
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

Request *RequestHandler::findRequest(QHostAddress addr, quint16 port, quint16 nonce)
{
    for (size_t i = 0; i < m_requests.size(); ++i)
    {
        Request *request = m_requests.at(i);
        if (request->getAddr() == addr && request->getPort() == port && request->getNonce() == nonce)
            return request;
    }
    return nullptr;
}

void RequestHandler::sendRequest(Request *request)
{
    std::cout << "sending request: " << request->getMessage().toStdString() << std::endl;
    m_sock.writeDatagram(request->getMessage().toUtf8(), request->getAddr(), request->getPort());
}

void RequestHandler::makeRequest(QHostAddress addr, quint16 port, bool outgoing, QString message)
{
    Request *request;
    if (outgoing)
        request = new Request(addr, port, outgoing, this->getNonce(addr, port) + ":" + message, this);
    else
        request = new Request(addr, port, outgoing, message, this);
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
