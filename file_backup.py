from zipfile import ZipFile, ZIP_DEFLATED
import os.path


def readFileList():
    with open('filelist.cfg') as fp:
        lines = fp.readlines()
        fileList = [line.strip() for line in lines]
        return fileList

    # In case of error
    return []


fileList = readFileList()

# Note that if no compression parameter is given, the resulting zip file will not be compressed.
with ZipFile('c:\\temp\\file-backup.zip', mode='w', compression=ZIP_DEFLATED) as myzip:
    for file in fileList:
        fileBaseName = os.path.basename(file)
        myzip.write(file, arcname=fileBaseName)

