#include "address.h"

bool operator<(const Address &left, const Address &right)
{
    QString leftStr = left.host.toString() + ":" + left.port;
    QString rightStr = right.host.toString() + ":" + right.port;
    return leftStr < rightStr;
}

bool operator>(const Address &left, const Address &right)
{
    QString leftStr = left.host.toString() + ":" + left.port;
    QString rightStr = right.host.toString() + ":" + right.port;
    return leftStr > rightStr;
}

bool operator==(const Address &left, const Address &right)
{
    return left.host == right.host && left.port == right.port;
}
