./auto_clean.sh
kill -9 $(ps -ef|grep SERVER|grep -v grep|awk '{print $2}')
./auto_config.sh
cd ../server
./SERVER 11030 11034&
cd ../server2
./SERVER 11031 11035&
cd ../server3
./SERVER 11032 11036&
cd ../server4
./SERVER 11033 11037&