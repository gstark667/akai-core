#include <QtCrypto/QtCrypto>
#include <QApplication>
#include <QtCore/QSettings>
#include <QtCore/QCoreApplication>
#include <QtCore/QStandardPaths>
#include "request.h"
#include <iostream>


int main(int argc, char *argv[]) {
    if (argc != 2)
        return 1;
    QString name("whale");
    name += argv[1];
    std::cout << name.toStdString() << std::endl;
    QCoreApplication::setOrganizationName("akai");
    QCoreApplication::setApplicationName(name);
    QCA::Initializer init;
    QApplication a(argc, argv);
    std::cout << QStandardPaths::writableLocation(QStandardPaths::DataLocation).toStdString() << std::endl;
    RequestHandler r(&a);
    return a.exec();
}
