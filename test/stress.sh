#!/bin/sh
# Usage: stress.sh UPLOAD_URL PROGRESS_URL
#

i=0
LIMIT="10k"
FILE="100"
#trap 'kill_all' SIGINT SIGTERM

while [ "1" == "1" ]
do
for j in $(seq 5)
do
i=`expr $i + 1`
echo "Upload $i"
curl --limit-rate $LIMIT -F pouet=@$FILE $1?X-Progress-ID=$i &
sh client.sh $i $2 &
i=`expr $i + 1`
echo "Upload $i"
curl --limit-rate $LIMIT -F pouet=@$FILE $1?X-Progress-ID=$i &
sh client.sh $i $2 &
i=`expr $i + 1`
echo "Upload $i"
curl --limit-rate $LIMIT -F pouet=@$FILE $1?X-Progress-ID=$i &
sh client.sh $i $2 &
i=`expr $i + 1`
echo "Upload $i"
curl --limit-rate $LIMIT -F pouet=@$FILE $1?X-Progress-ID=$i &
sh client.sh $i $2 &
i=`expr $i + 1`
echo "Upload $i"
curl --limit-rate $LIMIT -F pouet=@$FILE $1?X-Progress-ID=$i &
sh client.sh $i $2 &
i=`expr $i + 1`
echo "Upload $i"
curl --limit-rate $LIMIT -F pouet=@$FILE $1?X-Progress-ID=$i &
sh client.sh $i $2 &
done

wait
done
