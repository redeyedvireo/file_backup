from zipfile import ZipFile, ZIP_DEFLATED
from cryptography.fernet import Fernet
import os.path
import sys

zipFilePath = 'c:\\temp\\file-backup.zip'

def encryptFile(fileName, key):
    with open(fileName) as fp:
        contents = fp.read()
        print('Original:')
        print(contents)

        tempKey = Fernet.generate_key()
        encrKey = Fernet(tempKey)
        messageBytes = bytes(contents, 'utf8')
        encryptedContents = encrKey.encrypt(messageBytes)

        with open('test_encrypted.bin', 'wb') as outputFile:
            outputFile.write(encryptedContents)


def readFileList(fileName):
    with open(fileName) as fp:
        lines = fp.readlines()
        fileList = [line.strip() for line in lines]
        return fileList


def createZipFile(filePath):
    # Note that if no compression parameter is given, the resulting zip file will not be compressed.
    with ZipFile(filePath, mode='w', compression=ZIP_DEFLATED) as myzip:
        for file in fileList:
            fileBaseName = os.path.basename(file)
            myzip.write(file, arcname=fileBaseName)


# ------------------ Start ------------------
encryptFile('filelist.cfg', 'mykey')

#fileList = readFileList('filelist.cfg')
#createZipFile(zipFilePath)
