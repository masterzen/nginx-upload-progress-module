#!/bin/sh
# usage: client.sh UPLOAD_ID PROGRESS_URL
cont=""
while [ "$cont" != "new Object({ 'state' : 'done' })" ]
do
	cont=`curl -s -H "x-progress-id: $1" $2 | sed -e 's/[\n\r]//'`
	echo "[$1] '$cont'"
done
