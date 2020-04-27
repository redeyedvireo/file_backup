import sys
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

        encryptedContents = encryptBuffer(contents, password)

        outputFilePath = os.path.join(directory, outputFileName)
        with open(outputFilePath, 'wb') as outputFile:
            outputFile.write(encryptedContents)


def encryptBuffer(buffer, password):
    """ buffer must be bytes. """
    tempKey = generateKey(password)
    encrKey = Fernet(tempKey)
    return encrKey.encrypt(buffer)


def decryptFile(directory, fileName, outputFileName, password):
    filePath = os.path.join(directory, fileName)

    with open(filePath, 'rb') as fp:
        contents = fp.read()

        decryptedContents = decryptBuffer(contents, password)

        outputFilePath = os.path.join(directory, outputFileName)
        with open(outputFilePath, 'wb') as outputFile:
            outputFile.write(decryptedContents)


def decryptBuffer(buffer, password):
    """ Buffer must be bytes. """
    tempKey = generateKey(password)
    encrKey = Fernet(tempKey)
    return encrKey.decrypt(buffer)


def readEncryptedFile(directory, fileName, password):
    filePath = os.path.join(directory, fileName)

    with open(filePath, 'rb') as fp:
        contents = fp.read()

        decryptedContents = decryptBuffer(contents, password)

        return decryptedContents.decode()


def readEncryptedFileList(configFileDirectory, configFileName, password):
    contents = readEncryptedFile(configFileDirectory, configFileName, password)

    fileList = contents.split()
    return fileList


def readAndEncryptFile(directory, fileName, password):
    """ Reads a file, and encrypts its contents.
    :param directory: Directory where the file resides
    :param fileName: Name of file
    :param password: Password used to encrypt the file
    :return: The contents of the file, encrypted
    """
    filePath = os.path.join(directory, fileName)

    with open(filePath, 'rb') as fp:
        contents = fp.read()

        return encryptBuffer(contents, password)


def writeEncryptedFileList(configFileDirectory, configFileName, fileList, password):
    writeEncryptedFile(configFileDirectory, configFileName, "\n".join(fileList), password)


def writeEncryptedFile(configFileDirectory, configFileName, fileContents, password):
    encryptedContents = encryptBuffer(fileContents.encode(), password)

    outputFilePath = os.path.join(configFileDirectory, configFileName)
    with open(outputFilePath, 'wb') as outputFile:
        outputFile.write(encryptedContents)


def readFileList(fileName):
    """ Deprecated - does not handle encryption. """
    with open(fileName) as fp:
        lines = fp.readlines()
        fileList = [line.strip() for line in lines]
        return fileList


def addFileToList(configFileDirectory, configFileName, filePathToAdd, password):
    fileList = readEncryptedFileList(configFileDirectory, configFileName, password)

    # Make sure the file exists
    if os.path.exists(filePathToAdd):
        fileList.append(filePathToAdd)
        writeEncryptedFileList(configFileDirectory, configFileName, fileList, password)
    else:
        raise FileNotFoundError('{} not found.'.format(filePathToAdd))


def removeFileFromList(configFileDirectory, configFileName, lineNumberToRemove, password):
    fileList = readEncryptedFileList(configFileDirectory, configFileName, password)

    if lineNumberToRemove < len(fileList):
        del fileList[lineNumberToRemove]
        writeEncryptedFileList(configFileDirectory, configFileName, fileList, password)
    else:
        raise IndexError('Invalid entry.')


def printFileList(configFileDirectory, configFileName, password):
    fileList = readEncryptedFileList(configFileDirectory, configFileName, password)

    if len(fileList) > 0:
        for index, fileItem in enumerate(fileList):
            print('{}) {}'.format(index, fileItem))
    else:
        print('File empty.')


def createZipFile(configFileDirectory, configFileName, zipFilePath, zipFileName, password):
    fileList = readEncryptedFileList(configFileDirectory, configFileName, password)

    outputFilePath = os.path.join(zipFilePath, zipFileName)

    # Note that if no compression parameter is given, the resulting zip file will not be compressed.
    with ZipFile(outputFilePath, mode='w', compression=ZIP_DEFLATED) as myzip:
        for file in fileList:
            if os.path.exists(file):
                directory = os.path.dirname(file)
                fileBaseName = os.path.basename(file)
                fileBase, fileExtension = os.path.splitext(fileBaseName)
                newFileName = '{}_encr{}'.format(fileBase, fileExtension)
                encryptedFileContents = readAndEncryptFile(directory, fileBaseName, password)
                myzip.writestr(newFileName, encryptedFileContents)
            else:
                print('{} does not exist.  Skipping.'.format(file))


# ------------------ Start ------------------
if __name__ == "__main__":
    scriptDir = os.path.dirname(os.path.realpath(__file__))
    argParser = argparse.ArgumentParser()

    argParser.add_argument('-d', '--display', help='Display current list of files to back up', action='store_true')
    argParser.add_argument('-a', '--add', help='Add a file to back up', type=str)
    argParser.add_argument('-r', '--remove', help='Remove a file from the back up list', type=str)
    argParser.add_argument('-z', '--zip', help='Create Zip file', action='store_true')

    args = argParser.parse_args()

    # The password is 'mypw'

    try:
        if args.display:
            filePassword = getpass.getpass()
            printFileList(scriptDir, gEncryptedConfigFileName, filePassword)

        elif args.zip:
            filePassword = getpass.getpass()
            createZipFile(scriptDir, gEncryptedConfigFileName, gDestPath, gZipFileName, filePassword)
            print('Created {}'.format(os.path.join(gDestPath, gZipFileName)))

        elif args.add:
            filePassword = getpass.getpass()

            addFileToList(scriptDir, gEncryptedConfigFileName, args.add, filePassword)

            print('Added: {}\n'.format(args.add))

            # Print the complete list
            printFileList(scriptDir, gEncryptedConfigFileName, filePassword)  # The password is 'mypw'

        elif args.remove:
            filePassword = getpass.getpass()
            removeFileFromList(scriptDir, gEncryptedConfigFileName, int(args.remove), filePassword)

            print('Removed item {}\n'.format(args.remove))

            # Print the complete list
            printFileList(scriptDir, gEncryptedConfigFileName, filePassword)  # The password is 'mypw'

    except InvalidToken:
        print('Incorrect password')
    except IndexError as inst:
        print(inst)
    except FileNotFoundError as inst:
        print(inst)
    except:
        print('Unexpected error:', sys.exc_info()[0])
