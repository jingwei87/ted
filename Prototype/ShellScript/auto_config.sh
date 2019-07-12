cd ..
cd client
make -j6
cd ../keyServer
make -j6
cd ../server
make -j6
cd ..
cp -R server server2
cp -R server server3
cp -R server server4
