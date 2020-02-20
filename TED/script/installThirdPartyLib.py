#!/bin/python3

import os
import sys
import glob

dependentPackage_Dir = "./dependent-package/"
outputPackage_Dir = "./ThirdPartyLib/"
tarCommandPrefix = "tar -zxvf "
tarDir = " --directory "

# get the all tar file in under the dependent package dir
# return: all package file names under the dir 
def GetDependentPackageName(dirName):
    fileList = glob.glob(dependentPackage_Dir + "*tar*", recursive=True)
    print(fileList)
    return fileList

# un-compress all given packages to output path
# return: un-compress all packages to a given path
def UnCompressPackage(fileList, outputPath):
    # check whether the output path is exists
    if (os.path.exists(outputPath) == True):
        print("third libraries output path: %s", outputPath)
    else:
        print("third libraries output path not exists: %s")
        os.mkdir(outputPath)
    
    # un-compress input packages
    for file in fileList:
        cmd = tarCommandPrefix + file + tarDir + outputPath
        print(cmd)
        os.system(cmd)


if __name__ == "__main__":
    fileList = GetDependentPackageName(dependentPackage_Dir)
    UnCompressPackage(fileList, outputPackage_Dir)

    for file in fileList:
        # install for leveldb
        if (file.count("leveldb") != 0):
            wholeCmd = ""
            print("Install %s", file)
            file = file.replace(".tar.gz","")
            file = file.replace(dependentPackage_Dir, outputPackage_Dir)
            cmd = "cd " + file + ";"
            print(cmd)
            wholeCmd = wholeCmd + cmd
            # os.system(cmd)
            cmd = "mkdir -p build" + ";"
            wholeCmd = wholeCmd + cmd
            cmd = "cd build" + ";" + "cmake .." + ";" + "make -j2" + ";"
            wholeCmd = wholeCmd + cmd
            print(wholeCmd)
            os.system(wholeCmd)
        # install for openssl 
        elif (file.count("openssl") != 0):
            wholeCmd = ""
            print("Install %s", file)
            file = file.replace(".tar.gz","")
            file = file.replace(dependentPackage_Dir, outputPackage_Dir)
            cmd = "cd " + file + ";"
            wholeCmd = wholeCmd + cmd
            cmd = "./config " + ";" + "make -j2" + ";" + "sudo make install" + ";"
            wholeCmd = wholeCmd + cmd
            print(wholeCmd)
            os.system(wholeCmd)
        else:
            print("All libraries finished")
            break
    
