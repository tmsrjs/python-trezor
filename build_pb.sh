#!/bin/bash
CURDIR=$(pwd)
mkdir -p $CURDIR/pb2/
echo > $CURDIR/pb2/__init__.py

TARGET=trezorlib/messages/
rm -f $TARGET/*

for i in types messages storage ; do
    # Compile .proto files to python2 modules using google protobuf library
    cd $CURDIR/../trezor-common/protob
    protoc --python_out=$CURDIR/pb2/ -I/usr/include -I. $i.proto

    # Convert google protobuf library to trezor's internal format
    cd $CURDIR
    ./tools/pb2py $i $TARGET 1
done
