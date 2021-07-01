#include "widget.h"
#include "ui_widget.h"

#include <QCryptographicHash>
#include <QFileDialog>

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
}

Widget::~Widget()
{
    delete ui;
}


void Widget::on_TextString_textChanged(const QString &arg1)
{
    ui->HexString->setReadOnly(true);
    ui->pushButton->setDisabled(true);

    QString plaintext = ui->TextString->text();

    QByteArray md5 = QCryptographicHash::hash(plaintext.toLocal8Bit(), QCryptographicHash::Md5);
    ui->MD5Value->setText(md5.toHex().toUpper());

    QByteArray sha1 = QCryptographicHash::hash(plaintext.toLocal8Bit(), QCryptographicHash::Sha1);
    ui->SHA1Value->setText(sha1.toHex().toUpper());

    QByteArray sha256 = QCryptographicHash::hash(plaintext.toLocal8Bit(), QCryptographicHash::Sha256);
    ui->SHA256Value->setText(sha256.toHex().toUpper());

    QByteArray sha384 = QCryptographicHash::hash(plaintext.toLocal8Bit(), QCryptographicHash::Sha384);
    ui->SHA384Value->setText(sha384.toHex().toUpper());

    QByteArray sha512 = QCryptographicHash::hash(plaintext.toLocal8Bit(), QCryptographicHash::Sha512);
    ui->SHA512Value->setText(sha512.toHex().toUpper());

    QByteArray sha3_256 = QCryptographicHash::hash(plaintext.toLocal8Bit(), QCryptographicHash::Sha3_256);
    ui->SHA3256Value->setText(sha3_256.toHex().toUpper());

    QByteArray sha3_512 = QCryptographicHash::hash(plaintext.toLocal8Bit(), QCryptographicHash::Sha3_512);
    ui->SHA3512Value->setText(sha3_512.toHex().toUpper());

    if(ui->TextString->text() == "")
    {
        ui->HexString->setReadOnly(false);
        ui->pushButton->setDisabled(false);
    }
}

void Widget::on_HexString_textChanged(const QString &arg1)
{
    ui->TextString->setReadOnly(true);
    ui->pushButton->setDisabled(true);

    QString plaintext = ui->HexString->text();

    QByteArray md5 = QCryptographicHash::hash(QByteArray::fromHex(plaintext.toLocal8Bit()), QCryptographicHash::Md5);
    ui->MD5Value->setText(md5.toHex().toUpper());

    QByteArray sha1 = QCryptographicHash::hash(QByteArray::fromHex(plaintext.toLocal8Bit()), QCryptographicHash::Sha1);
    ui->SHA1Value->setText(sha1.toHex().toUpper());

    QByteArray sha256 = QCryptographicHash::hash(QByteArray::fromHex(plaintext.toLocal8Bit()), QCryptographicHash::Sha256);
    ui->SHA256Value->setText(sha256.toHex().toUpper());

    QByteArray sha384 = QCryptographicHash::hash(QByteArray::fromHex(plaintext.toLocal8Bit()), QCryptographicHash::Sha384);
    ui->SHA384Value->setText(sha384.toHex().toUpper());

    QByteArray sha512 = QCryptographicHash::hash(QByteArray::fromHex(plaintext.toLocal8Bit()), QCryptographicHash::Sha512);
    ui->SHA512Value->setText(sha512.toHex().toUpper());

    QByteArray sha3_256 = QCryptographicHash::hash(QByteArray::fromHex(plaintext.toLocal8Bit()), QCryptographicHash::Sha3_256);
    ui->SHA3256Value->setText(sha3_256.toHex().toUpper());

    QByteArray sha3_512 = QCryptographicHash::hash(QByteArray::fromHex(plaintext.toLocal8Bit()), QCryptographicHash::Sha3_512);
    ui->SHA3512Value->setText(sha3_512.toHex().toUpper());

    if(ui->HexString->text() == "")
    {
        ui->TextString->setReadOnly(false);
        ui->pushButton->setDisabled(false);
    }
}

QByteArray createFileHash(const QString &fileName,QCryptographicHash::Algorithm hashType)
{
    QByteArray result;
    QFile *file=new QFile(fileName);
    if(!file->open(QFile::ReadOnly))
    return result;

    QCryptographicHash *hash=new QCryptographicHash(hashType);
    while(!file->atEnd())
    {
        hash->addData(file->read(8192));
    }

    result=hash->result();
    delete hash;
    hash=nullptr;
    delete file;
    file=nullptr;

    return result;
}


void Widget::on_pushButton_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, "Choose file", QDir::currentPath(), "All files (*.*) ;; Document (*.doc *.rtf);; Image (*.png *.jpg)");

    ui->file->setText(filePath);

    QByteArray md5 = createFileHash(filePath, QCryptographicHash::Md5);
    ui->MD5Value->setText(md5.toHex().toUpper());

    QByteArray sha1 = createFileHash(filePath, QCryptographicHash::Sha1);
    ui->SHA1Value->setText(sha1.toHex().toUpper());

    QByteArray sha256 = createFileHash(filePath, QCryptographicHash::Sha256);
    ui->SHA256Value->setText(sha256.toHex().toUpper());

    QByteArray sha384 = createFileHash(filePath, QCryptographicHash::Sha384);
    ui->SHA384Value->setText(sha384.toHex().toUpper());

    QByteArray sha512 = createFileHash(filePath, QCryptographicHash::Sha512);
    ui->SHA512Value->setText(sha512.toHex().toUpper());

    QByteArray sha3_256 = createFileHash(filePath, QCryptographicHash::Sha3_256);
    ui->SHA3256Value->setText(sha3_256.toHex().toUpper());

    QByteArray sha3_512 = createFileHash(filePath, QCryptographicHash::Sha3_512);
    ui->SHA3512Value->setText(sha3_512.toHex().toUpper());
}

void Widget::on_btnClose_clicked()
{
    close();
}
