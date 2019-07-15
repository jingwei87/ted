./auto_clean.sh
kill -9 $(ps -ef|grep SERVER|grep -v grep|awk '{print $2}')
kill -9 $(ps -ef|grep KEYMANAGER|grep -v grep|awk '{print $2}')
./auto_config.sh
cd ../server
./SERVER 11030&
cd ../server2
./SERVER 11031&
cd ../server3
./SERVER 11032&
cd ../server4
./SERVER 11033&
cd ../keyServer
./KEYMANAGER 19301&