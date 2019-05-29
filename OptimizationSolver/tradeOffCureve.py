#!/usr/bin/python3
from scipy import stats
import matplotlib.pyplot as plt
import numpy as np 
import seaborn as sns  
import sys

Storage_loss_small = [680906,
1543772,
1574687,
3028131,
3150323,
7172424,
10093330,
10228088,
21342209,
22024771]

Security_gain_small = [0.138698,
0.337563,
0.345772,
0.728133,
0.765342,
1.771902,
2.463096,
2.819592,
5.452124,
5.682173]

#print(Storage_loss_large)
#print(Security_gain_large)

type_Storage = Storage_loss_small
type_Security = Security_gain_small

#plt.plot(type_Storage, type_Security, label="trade-off curve")
#plt.plot(type_Storage, type_Storage, label="baseline")
plt.plot(type_Storage, type_Security)

plt.legend(fontsize=18)
plt.ylabel("Computation Time", fontsize=18)
plt.xlabel("Amount of Unique Chunks", fontsize=18)
#plt.ylim(0, 1)
#plt.xlim(0, 1)
#plt.xscale('log')
#plt.xlim([1,10**8])
plt.grid(True)
plt.show()