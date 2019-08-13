./auto_clean.sh
kill -9 $(ps -ef|grep SERVER|grep -v grep|awk '{print $2}')
kill -9 $(ps -ef|grep KEYMANAGER|grep -v grep|awk '{print $2}')
./auto_config.sh
cd ../server
./SERVER 1130&
cd ../server2
./SERVER 1131&
cd ../server3
./SERVER 1132&
cd ../server4
./SERVER 1133&
cd ../keyServer
./KEYMANAGER 19301&