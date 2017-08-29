#ifndef H_CRYPTO
#define H_CRYPTO

#include <QtCore/QString>
#include <QtCore/QException>
#include <gpgme.h>

class CryptoException: public QException
{
private:
    gpgme_error_t m_error;

public:
    CryptoException(gpgme_error_t error);
};

class Crypto
{
private:
    QString m_fingerPrint;
    gpgme_ctx_t m_ctx;
    gpgme_key_t m_key;
    gpgme_data_t m_data;

public:
    Crypto(QString fingerPrint);
    ~Crypto();

    QString sign(QString text);
    QString encrypt(QString receiver, QString text);
};

#endif
