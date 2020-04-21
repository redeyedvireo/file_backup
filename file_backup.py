from zipfile import ZipFile, ZIP_DEFLATED
from cryptography.fernet import Fernet, InvalidToken
import os.path
import os
import argparse
import getpass
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

gDestPath = 'c:\\temp'
gZipFileName = 'file-backup.zip'
gConfigFileName = 'filelist.cfg'
gEncryptedConfigFileName = 'filelist.bin'


def generateKey(password):
    encoded_password = password.encode()  # Convert to type bytes
    salt = b'potato_chips_salty'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(encoded_password))  # Can only use kdf once


def encryptFile(directory, fileName, outputFileName, password):
    filePath = os.path.join(directory, fileName)

    with open(filePath, 'rb') as fp:
        contents = fp.read()

        # tempKey = generateKey(password)
        # encrKey = Fernet(tempKey)
        # encryptedContents = encrKey.encrypt(contents)

        encryptedContents = encryptBuffer(contents, password)

        outputFilePath = os.path.join(directory, outputFileName)
        with open(outputFilePath, 'wb') as outputFile:
            outputFile.write(encryptedContents)


def encryptBuffer(buffer, password):
    ''' buffer must be bytes. '''
    tempKey = generateKey(password)
    encrKey = Fernet(tempKey)
    return encrKey.encrypt(buffer)


def decryptFile(directory, fileName, outputFileName, password):
    filePath = os.path.join(directory, fileName)

    with open(filePath, 'rb') as fp:
        contents = fp.read()

        tempKey = generateKey(password)
        encrKey = Fernet(tempKey)
        descriptedContents = encrKey.decrypt(contents)

        outputFilePath = os.path.join(directory, outputFileName)
        with open(outputFilePath, 'wb') as outputFile:
            outputFile.write(descriptedContents)


def readEncryptedFile(directory, fileName, password):
    filePath = os.path.join(directory, fileName)

    with open(filePath, 'rb') as fp:
        contents = fp.read()

        tempKey = generateKey(password)
        encrKey = Fernet(tempKey)
        try:
            descriptedContents = encrKey.decrypt(contents)
        except InvalidToken:
            print('Incorrect password')
            return '', False

        return descriptedContents.decode(), True


def readEncryptedFileList(configFileDirectory, configFileName, password):
    contents, success = readEncryptedFile(configFileDirectory, configFileName, password)

    if success:
        fileList = contents.split()
        return fileList, True
    else:
        return [], False


def writeEncryptedFileList(configFileDirectory, configFileName, fileList, password):
    writeEncryptedFile(configFileDirectory, configFileName, "\n".join(fileList), password)


def writeEncryptedFile(configFileDirectory, configFileName, fileContents, password):
    encryptedContents = encryptBuffer(fileContents.encode(), password)

    outputFilePath = os.path.join(configFileDirectory, configFileName)
    with open(outputFilePath, 'wb') as outputFile:
        outputFile.write(encryptedContents)


def readFileList(fileName):
    with open(fileName) as fp:
        lines = fp.readlines()
        fileList = [line.strip() for line in lines]
        return fileList


def addFileToList(configFileDirectory, configFileName, lineToAdd, password):
    fileList, success = readEncryptedFileList(configFileDirectory, configFileName, password)

    if success:
        # print('File list')
        # for item in fileList:
        #     print(item)
        fileList.append(lineToAdd)
        writeEncryptedFileList(configFileDirectory, configFileName, fileList, password)


def createZipFile(filePath):
    # Note that if no compression parameter is given, the resulting zip file will not be compressed.
    with ZipFile(filePath, mode='w', compression=ZIP_DEFLATED) as myzip:
        for file in fileList:
            fileBaseName = os.path.basename(file)
            myzip.write(file, arcname=fileBaseName)


# ------------------ Start ------------------
if __name__ == "__main__":
    scriptDir = os.path.dirname(os.path.realpath(__file__))
    argParser = argparse.ArgumentParser()

    argParser.add_argument('--display', help='Display current list of files to back up', action='store_true')
    argParser.add_argument('--add', help='Add a file to back up', type=str)
    argParser.add_argument('--remove', help='Remove a file from the back up list', type=str)

    # Note: don't get credentials of any kind on the command-line.  Instead, prompt for this at runtime.
    # argParser.add_argument('ProxyUserName', help='User name for proxy authentication', type=str)
    # argParser.add_argument('ProxyPassword', help='Password for proxy authentication', type=str)

    args = argParser.parse_args()

    if args.display:
        filePassword = getpass.getpass()
        contents, success = readEncryptedFile(scriptDir, gEncryptedConfigFileName, filePassword)    # The password is 'mypw'

        if success:
            print(contents)

    elif args.add:
        filePassword = getpass.getpass()
        print('Added: {}'.format(args.add))
        addFileToList(scriptDir, gEncryptedConfigFileName, args.add, filePassword)

        # Should now print the complete list
        contents, success = readEncryptedFile(scriptDir, gEncryptedConfigFileName, filePassword)    # The password is 'mypw'

        if success:
            print(contents)

    # encryptFile(scriptDir, configFileName, encryptedConfigFileName, 'mypw')
    # decryptFile(scriptDir, encryptedConfigFileName, 'decrypted_filelist.cfg', 'mypw')

    #fileList = readFileList('filelist.cfg')
    #createZipFile(zipFilePath)
