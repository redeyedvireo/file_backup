# file_backup
A backup script in Python

## Config file
The config file should be an INI file, and have the following format:
```text
[Config]
fileListPath = <Path to the encrypted file list file (including the file's name)>
zipFilePath = <Path to the zip file (including the file's name)>
extractionDir = <Directory where the zip file will be extracted.>
```

An example config file:
```text
[Config]
fileListPath = c:\backup\filelist.bin
zipFilePath = c:\temp\file-backup.zip
extractionDir = c:\temp
```

The file list file is an encrypted file that contains a list of the file paths to be backed up.
