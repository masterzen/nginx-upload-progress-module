#!/bin/sh

cont=""
while [ "$cont" != "new Object({ 'state' : 'done' })" ]
do
	cont=`curl -s -H "x-progress-id: $1" http://172.16.10.67/progress | sed -e 's/[\n\r]//'`
	echo "[$1] '$cont'"
done
