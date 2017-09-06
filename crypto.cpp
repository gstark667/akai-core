#include "crypto.h"

#include <iostream>

CryptoException::CryptoException(gpgme_error_t error): QException()
{
    m_error = error;
    std::cout << "throwing crypto exception: " << gpgme_strerror(error) << std::endl;
}

Crypto::Crypto(QString fingerPrint)
{
    m_fingerPrint = fingerPrint;

    char buf[2048];
    size_t read_bytes;
    int tmp;
    gpgme_error_t err;

    gpgme_engine_info_t enginfo;

    setlocale (LC_ALL, "");
    char *version = (char *) gpgme_check_version(NULL);
    printf("version=%s\n",version);
    gpgme_set_locale(NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));

    err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
    if(err != GPG_ERR_NO_ERROR) printf("Got error");

    char *protocol = (char *) gpgme_get_protocol_name(GPGME_PROTOCOL_OpenPGP);
    printf("Protocol name: %s\n",protocol);

    err = gpgme_get_engine_info(&enginfo);
    if(err != GPG_ERR_NO_ERROR) throw CryptoException(err);
    printf("file=%s, home=%s\n",enginfo->file_name,enginfo->home_dir);

    err = gpgme_new(&m_ctx);
    if(err != GPG_ERR_NO_ERROR) throw CryptoException(err);

    err = gpgme_set_protocol(m_ctx,GPGME_PROTOCOL_OpenPGP);
    if(err != GPG_ERR_NO_ERROR) throw CryptoException(err);

    err = gpgme_ctx_set_engine_info (m_ctx, GPGME_PROTOCOL_OpenPGP, enginfo->file_name,enginfo->home_dir);
    if(err != GPG_ERR_NO_ERROR) throw CryptoException(err);

    gpgme_set_armor(m_ctx, 1);

    err = gpgme_data_new(&m_data);
    if(err != GPG_ERR_NO_ERROR) throw CryptoException(err);

    err = gpgme_data_set_encoding(m_data,GPGME_DATA_ENCODING_ARMOR);
    if(err != GPG_ERR_NO_ERROR) throw CryptoException(err);

    tmp = gpgme_data_get_encoding(m_data);
    if(tmp == GPGME_DATA_ENCODING_ARMOR) {
       printf("encode ok\n");
    } else {
       printf("encode broken\n");
    }

    if (m_fingerPrint == "")
    {
        std::cout << "generating new key" << std::endl;
        err = gpgme_op_createkey(m_ctx, "asdfasdf", NULL, 0, 0, NULL, GPGME_CREATE_NOEXPIRE | GPGME_CREATE_ENCR | GPGME_CREATE_SIGN | GPGME_CREATE_NOPASSWD | GPGME_CREATE_FORCE);
        if(err != GPG_ERR_NO_ERROR) throw CryptoException(err);
        gpgme_genkey_result_t genkey = gpgme_op_genkey_result(m_ctx);
        m_fingerPrint = genkey->fpr;
        std::cout << "new fingerprint: " << m_fingerPrint.toStdString() << std::endl;
    }

    err = gpgme_get_key(m_ctx, m_fingerPrint.toStdString().c_str(), &m_key, true);
    if (err != GPG_ERR_NO_ERROR)
        throw CryptoException(err);
}

Crypto::~Crypto()
{
    gpgme_data_release(m_data);
    gpgme_release(m_ctx);
}

QString Crypto::encrypt(QString receiver, QString text)
{
    std::cout << "encrypting for: " << receiver.toStdString() << ": " << text.toStdString() << std::endl;
    gpgme_key_t receiverKey[2];
    gpgme_error_t error;
    error = gpgme_get_key(m_ctx, receiver.toStdString().c_str(), &receiverKey[0], false);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);
    receiverKey[1] = 0;

    // we need to copy the string into a new pointer so it doesn't get deleted
    char *data = (char*)malloc(sizeof(char) * text.size() + 1);
    memcpy(data, text.toStdString().c_str(), text.size() + 1);

    gpgme_data_t in, out;
    error = gpgme_data_new_from_mem(&in, data, text.size(), false);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);
    error = gpgme_data_new(&out);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);
    error = gpgme_op_encrypt_sign(m_ctx, receiverKey, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);

    int ret;
    ret = gpgme_data_seek(out, 0, SEEK_SET);
    char buffer[2048] = "";
    QString output = "";
    while ((ret = gpgme_data_read(out, buffer, 2048)) > 0)
    {
        output += buffer;
    }
    gpgme_data_release(in);
    gpgme_data_release(out);
    return output;
}

QString Crypto::decrypt(QString &sender, QString crypt)
{
    // we need to copy the string into a new pointer so it doesn't get deleted
    char *data = (char*)malloc(sizeof(char) * crypt.size() + 1);
    memcpy(data, crypt.toStdString().c_str(), crypt.size() + 1);

    gpgme_error_t error;
    gpgme_data_t in, out;
    error = gpgme_data_new_from_mem(&in, data, crypt.size(), false);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);
    error = gpgme_data_new(&out);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);
    error = gpgme_op_decrypt_verify(m_ctx, in, out);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);

    int ret;
    ret = gpgme_data_seek(out, 0, SEEK_SET);
    char buffer[2048] = "";
    QString output = "";
    while ((ret = gpgme_data_read(out, buffer, 2048)) > 0)
    {
        output += buffer;
    }
    gpgme_data_release(in);
    gpgme_data_release(out);

    // TODO this probably needs to be freed
    gpgme_verify_result_t result = gpgme_op_verify_result(m_ctx);
    sender = QString(result->signatures[0].fpr);
    return buffer;
}

