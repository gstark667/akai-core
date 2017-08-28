#ifndef H_CRYPTO
#define H_CRYPTO

#include <QtCore/QString>
#include <gpgme.h>

class Crypto
{
private:
    QString m_fingerPrint;
    gpgme_ctx_t m_ctx;

public:
    Crypto(QString fingerPrint);
};

#endif
