QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = akai-whale
TEMPLATE = app


SOURCES += main.cpp \
        address.cpp \
        request.cpp

HEADERS  += request.h

#FORMS    += CryptWin.ui

LIBS += -lQt5Network -lqca-qt5 -lgpgme
INCLUDEPATH += /usr/include/qt/Qca-qt5/

