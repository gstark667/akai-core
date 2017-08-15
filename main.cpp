#include <QtCrypto/QtCrypto>
#include <QApplication>
#include <QtCore/QSettings>
#include <QtCore/QCoreApplication>
#include "request.h"


int main(int argc, char *argv[]) {
    QCoreApplication::setOrganizationName("akai");
    QCoreApplication::setApplicationName("whale");
	QCA::Initializer init;
	QApplication a(argc, argv);
	RequestHandler r(&a);
	return a.exec();
}
