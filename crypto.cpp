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

    //char *p;
    char buf[2048];
    size_t read_bytes;
    int tmp;
    //gpgme_ctx_t ceofcontext;
    gpgme_error_t err;

    gpgme_engine_info_t enginfo;

    /* The function `gpgme_check_version' must be called before any other
     * function in the library, because it initializes the thread support
     * subsystem in GPGME. (from the info page) */
    setlocale (LC_ALL, "");
    char *version = (char *) gpgme_check_version(NULL);
    printf("version=%s\n",version);
    //free(version);
    /* set locale, because tests do also */
    gpgme_set_locale(NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));

    err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
    if(err != GPG_ERR_NO_ERROR) printf("Got error");

    char *protocol = (char *) gpgme_get_protocol_name(GPGME_PROTOCOL_OpenPGP);
    printf("Protocol name: %s\n",protocol);
    //free(protocol);

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

    err = gpgme_get_key(m_ctx, fingerPrint.toStdString().c_str(), &m_key, true);
    if (err != GPG_ERR_NO_ERROR)
        throw CryptoException(err);

    /*err = gpgme_op_export(m_ctx,NULL,0,m_data);
    if(err != GPG_ERR_NO_ERROR) throw CryptoException(err);

    read_bytes = gpgme_data_seek (m_data, 0, SEEK_END);
    printf("end is=%d\n",read_bytes);
    if(read_bytes == -1) {
        throw CryptoException(err);
    }
    read_bytes = gpgme_data_seek (m_data, 0, SEEK_SET);
    printf("start is=%d (should be 0)\n",read_bytes);*/
}

Crypto::~Crypto()
{
    gpgme_data_release(m_data);
    gpgme_release(m_ctx);
}

QString Crypto::sign(QString text)
{
    gpgme_data_t in, out;
    gpgme_error_t error;
    error = gpgme_data_new_from_mem(&in, text.toStdString().c_str(), text.size(), false);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);
    error = gpgme_data_new(&out);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);
    error = gpgme_op_sign(m_ctx, in, out, GPGME_SIG_MODE_CLEAR);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);

    int ret;
    ret = gpgme_data_seek(out, 0, SEEK_SET);
    char buffer[2048];
    QString output = "";
    while ((ret = gpgme_data_read(out, buffer, 2048)) > 0)
    {
        output += buffer;
    }
    return output;
}

QString Crypto::encrypt(QString receiver, QString text)
{
    gpgme_key_t receiverKey[2];
    gpgme_error_t error;
    error = gpgme_get_key(m_ctx, receiver.toStdString().c_str(), &receiverKey[0], false);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);
    receiverKey[1] = 0;

    gpgme_data_t in, out;
    error = gpgme_data_new_from_mem(&in, text.toStdString().c_str(), text.size(), false);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);
    error = gpgme_data_new(&out);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);
    error = gpgme_op_encrypt(m_ctx, receiverKey, GPGME_ENCRYPT_NO_ENCRYPT_TO, in, out);
    if (error != GPG_ERR_NO_ERROR)
        throw CryptoException(error);

    int ret;
    ret = gpgme_data_seek(out, 0, SEEK_SET);
    char buffer[2048];
    QString output = "";
    while ((ret = gpgme_data_read(out, buffer, 2048)) > 0)
    {
        output += buffer;
    }
    return output;

    //gpgme_op_encrypt(m_ctx, receiverKey, NULL, data, 
}

