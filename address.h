#ifndef H_ADDRESS
#define H_ADDRESS

#include <QtNetwork/QHostAddress>

typedef struct
{
    QHostAddress host;
    quint16      port;
} Address;

bool operator <(const Address&, const Address&);
bool operator >(const Address&, const Address&);
bool operator ==(const Address&, const Address&);

#endif
