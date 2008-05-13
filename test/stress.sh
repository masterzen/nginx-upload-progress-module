#!/bin/sh
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
curl --limit-rate $LIMIT -F pouet=@$FILE http://172.16.10.67/upload.html?X-Progress-ID=$i &
sh client.sh $i &
i=`expr $i + 1`
echo "Upload $i"
curl --limit-rate $LIMIT -F pouet=@$FILE http://172.16.10.67/upload.html?X-Progress-ID=$i &
sh client.sh $i &
i=`expr $i + 1`
echo "Upload $i"
curl --limit-rate $LIMIT -F pouet=@$FILE http://172.16.10.67/upload.html?X-Progress-ID=$i &
sh client.sh $i &
i=`expr $i + 1`
echo "Upload $i"
curl --limit-rate $LIMIT -F pouet=@$FILE http://172.16.10.67/upload.html?X-Progress-ID=$i &
sh client.sh $i &
i=`expr $i + 1`
echo "Upload $i"
curl --limit-rate $LIMIT -F pouet=@$FILE http://172.16.10.67/upload.html?X-Progress-ID=$i &
sh client.sh $i &
i=`expr $i + 1`
echo "Upload $i"
curl --limit-rate $LIMIT -F pouet=@$FILE http://172.16.10.67/upload.html?X-Progress-ID=$i &
sh client.sh $i &
done

wait
done
