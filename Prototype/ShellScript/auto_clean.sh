kill -9 $(ps -ef|grep SERVER|grep -v grep|awk '{print $2}')
kill -9 $(ps -ef|grep KEYMANAGER|grep -v grep|awk '{print $2}')
cd ..
rm -rf server2/
rm -rf server3/
rm -rf server4/

cd server
make clean

cd ../keyServer
make clean

cd ../client
make clean

cd lib
make clean