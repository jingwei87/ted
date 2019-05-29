#!/usr/bin/python3
from scipy import stats
import matplotlib.pyplot as plt
import numpy as np 
import seaborn as sns
import sys  

f_poutp = open("output_p", "r")
f_coutp = open("output_c", "r")
#data = F.read()
#print(data)
arr_p = []
arr_c = []

#for plot more clear, we add 1 for each item
arr_p_plot = []
arr_c_plot = []

counter = 0
count = 0
#print(len(F_p.readlines()))

for line_p in f_poutp.readlines():
    line_p = line_p.strip()
    count = str(line_p)
    arr_p_plot.append(int(count[0:12]) + 1)
    arr_p.append(int(count[0:12]))


for line_c in f_coutp.readlines():
    line_c = line_c.strip()
    count = str(line_c)
    arr_c_plot.append(float(count[0:12]) + 1)
    arr_c.append(float(count[0:12]))


arr_p.sort(reverse=True)
arr_c.sort(reverse=True)
arr_c_plot.sort(reverse=True)
arr_p_plot.sort(reverse=True)


x_p = []
x_c = []
dist_p = {}
dist_c = {}


for i in range(len(arr_p)):
    x_p.append(i)
    if (arr_p[i] in dist_p):
        dist_p[arr_p[i]] = dist_p[arr_p[i]] + 1
    else:
        dist_p[arr_p[i]] = 1

print(dist_p[1])
print(dist_p[2])
print(dist_p[3])
print(dist_p[4])
print(dist_p[5])


for i in range(len(arr_c)):
    x_c.append(i)
    if (arr_c[i] in dist_c):
        dist_c[arr_c[i]] = dist_c[arr_c[i]] + 1
    else:
        dist_c[arr_c[i]] = 1

print(dist_c)

print("Sum: " + str(sum(arr_p)))
print("Sum: " + str(sum(arr_c)))

if int(sys.argv[1]) == 1:
    print("for plaintext")
    #print(arr_p)   
    plt.plot(x_p, arr_p_plot)
    plt.plot(x_c, arr_c_plot)
else:
    print("for ciphertext")
    #print(arr_c)
    plt.plot(x_c, arr_c_plot)
    plt.plot(x_p, arr_p_plot)
print("The maximum count of plaintext chunks: " + str(max(arr_p)))
print("The amount of plaintext chunks: " + str(len(arr_p)))
print("The maximum count of ciphertext chunks: " + str(max(arr_c)))
print("The amount of ciphertext chunks: " + str(len(arr_c)))


plt.xlabel("chunk amount", fontsize=18)
plt.ylabel("frequency", fontsize=18)
plt.yscale('log')
#plt.xscale('log')

if int(sys.argv[1]) == 1:
    print("for plaintext")
    plt.ylim([1,10**8])
else:
    print("for ciphertext")
    plt.ylim([1,10**8])

plt.grid(False)
plt.show()






