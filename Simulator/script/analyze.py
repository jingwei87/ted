import sys  
import math
import hashlib

################# read the plaintext #########################
def read_plaintext(Plaintext):
    FilePlain = open(Plaintext, "r")
    FrequencyArrayP = []
    KeyFreqDictP = {}
    print("Start to count plaintext chunks!")
    for Lines in FilePlain:
        Lines = Lines.strip()
        Content = str(Lines)
        Pos = Content.rfind("\t")
        Frequency = int(Content[Pos+1:Pos+10])
        FrequencyArrayP.append(Frequency)
    print("Done!")
    return FrequencyArrayP.copy(), KeyFreqDictP.copy()

################# read the ciphertext ########################
def read_ciphertext(Ciphertext):
    FileCipher = open(Ciphertext, "r")
    FrequencyArrayC = []
    KeyFreqDictC = {}
    print("Start to count ciphertext chunks!")
    for Lines in FileCipher:
        Lines = Lines.strip()
        Content = str(Lines)
        Pos = Content.rfind("\t")
        Frequency = int(Content[Pos+1:Pos+10])
        FrequencyArrayC.append(Frequency)
        KeyId = Content[0:Pos-1]
        OriginalKeyId = Content[0:Pos-13]
        # KeyFreqDictC[KeyId] = Frequency
    print("Done!")
    return FrequencyArrayC.copy(), KeyFreqDictC.copy()




################## read single data set #######################

def read_single(DataSet):
    FilePlain = open(DataSet, "r")
    FrequencyArrayP = []
    print("Start to count plaintext chunks!")
    for Lines in FilePlain:
        Lines = Lines.strip()
        Content = str(Lines)
        Pos = Content.rfind("\t")
        Frequency = int(Content[Pos+1:Pos+10])
        FrequencyArrayP.append(Frequency)
        KeyId = Content[0:Pos-1]
        # filter out the chunk whose frequency is 1
        if (Frequency == 1):
            continue
        else:
            KeyFreqDictP[KeyId] = Frequency
    print("Read single data done!")
    return FrequencyArrayP


################### compute cosine ######################
def cal_cosine(KeyFreqDictP, KeyFreqDictC):
    SumP = 0 
    for key in KeyFreqDictP:
        SumP = SumP + KeyFreqDictP[key]

    SumC = 0
    for key in KeyFreqDictC:
        if KeyFreqDictP.__contains__(key):
            SumC = SumC + KeyFreqDictC[key]
    
    CosSum = 0
    for key in KeyFreqDictP:
        CosSum = CosSum + ((KeyFreqDictP[key] / SumP) * (KeyFreqDictC[key] / SumC))

    CosSumP = 0
    for key in KeyFreqDictP:
        CosSumP = CosSumP + (KeyFreqDictP[key] / SumP) ** 2 
    CosSumP = math.sqrt(CosSumP)

    CosSumC = 0
    for key in KeyFreqDictC:
        CosSumC = CosSumC + (KeyFreqDictC[key] / SumC) ** 2
    CosSumC = math.sqrt(CosSumC)

    CosSimilarity = (CosSum) / (CosSumC * CosSumP)
    return CosSimilarity

################## compute the amount of chunk in each unique #############
def cal_frequency_distance(FrequencyArrayP, FrequencyArrayC):
    x_p = []
    x_c = []
    dist_p = {}
    dist_c = {}
    for i in range(len(FrequencyArrayP)):
        x_p.append(i)
        if (dist_p.__contains__(FrequencyArrayP[i])):
            dist_p[FrequencyArrayP[i]] = dist_p[FrequencyArrayP[i]] + 1
        else: 
            dist_p[FrequencyArrayP[i]] = 1
    for i in range(len(FrequencyArrayC)):
        x_c.append(i)
        if (dist_c.__contains__(FrequencyArrayC[i])):
            dist_c[FrequencyArrayC[i]] = dist_c[FrequencyArrayC[i]] + 1
        else:
            dist_c[FrequencyArrayC[i]] = 1
    return dist_p.copy(), dist_c.copy()

def cal_average(InputArray):
    average = sum(InputArray) / len(InputArray)
    return average

def cal_variance(InputArray):
    average = cal_average(InputArray)
    variance = 0
    total = 0
    for i in range(len(InputArray)):
        total = total + (InputArray[i] - average) ** 2
    variance = total / (len(InputArray) - 1)
    return variance

def cal_Skewness(FrequencyArrayP, FrequencyArrayC):
    averageP = cal_average(FrequencyArrayP)
    averageC = cal_average(FrequencyArrayC)
    standVarianceP = math.sqrt(cal_variance(FrequencyArrayP))
    standVarianceC = math.sqrt(cal_variance(FrequencyArrayC))
    ##### for plaintext #####
    print("Plaintext: %f, %f, %f, %f" %(averageP, averageC, standVarianceP, standVarianceC))
    total = 0
    for i in range(len(FrequencyArrayP)):
        total = total + ((FrequencyArrayP[i] - averageP) / standVarianceP) ** 3
    skewnessP = total / len(FrequencyArrayP)
    print("Standard skewnessP threshold: " + str(math.sqrt(15 / len(FrequencyArrayP))))
    ##### for ciphertext #####
    total = 0
    for i in range(len(FrequencyArrayC)):
        total = total + ((FrequencyArrayC[i] - averageC) / standVarianceC) ** 3
    skewnessC = total / len(FrequencyArrayC)
    print("Standard skewnessC threshold: " + str(math.sqrt(15 / len(FrequencyArrayC))))
    return skewnessP, skewnessC


def cal_Kurtosis(FrequencyArrayP, FrequencyArrayC):
    averageP = cal_average(FrequencyArrayP)
    averageC = cal_average(FrequencyArrayC)
    standVarianceP = math.sqrt(cal_variance(FrequencyArrayP))
    standVarianceC = math.sqrt(cal_variance(FrequencyArrayC))
    ##### for plaintext #####
    kurtosisP = 0
    total = 0
    for i in range(len(FrequencyArrayP)):
        total = total + ((FrequencyArrayP[i] - averageP) / standVarianceP) ** 4
    kurtosisP = (total / len(FrequencyArrayP)) - 3
    print("Standard kurtosisP threshold: " + str(math.sqrt(96/ len(FrequencyArrayP))))
    ##### for ciphertext #####
    kurtosisC = 0
    total = 0
    for i in range(len(FrequencyArrayC)):
        total = total + ((FrequencyArrayC[i] - averageC) / standVarianceC) ** 4
    kurtosisC = (total / len(FrequencyArrayC)) - 3
    print("Standard kurtosisC threshold: " + str(math.sqrt(96 / len(FrequencyArrayC))))

    return kurtosisP, kurtosisC


### calculate for Kullback-Leibler divergence of the encrypted chunks distribution ###

def cal_KLD(FrequencyArray):
    KLDivergence = math.log(len(FrequencyArray), 2) - cal_entropy(FrequencyArray)
    return KLDivergence


################### calculate entropy of a given distribution ################

def cal_entropy(DataArray):
    TotalSum = sum(DataArray)
    Entropy = 0
    for item in range(len(DataArray)):
        Frequency = DataArray[item] / TotalSum
        Entropy = Entropy - (Frequency * math.log(Frequency, 2))

    return Entropy
    
    
################## filter ########################

def filter_freq(Limitation, DistFrequency):
    FilterCount = 0
    for freq in range(1, int(Limitation)+1, 1):
        if (DistFrequency.__contains__(freq)):
            FilterCount = FilterCount + DistFrequency[freq]       
    return FilterCount


if __name__ == "__main__":
    FrequencyArrayP = []
    KeyFreqDictP = {}
    FrequencyArrayC = []
    KeyFreqDictC = {}
    UniqueFreqItemNumP = {}
    UniqueFreqItemNumC = {}
    if (len(sys.argv) < 3):
        print("Usage: %s [**.pfreq] [**.cfreq]" %(str(sys.argv[0])))
        exit(1)
    
    print("----------------Read Data---------------")
    content1 = str(sys.argv[1])
    pos1 = content1.rfind(".")
    postfix1 = content1[pos1+1:pos1+6]
    print(postfix1)
    if (str(postfix1) == "pfreq"):
        FrequencyArrayP, KeyFreqDictP = read_plaintext(str(sys.argv[1]))
    elif (str(postfix1) == "cfreq"):
        FrequencyArrayP, KeyFreqDictP = read_ciphertext(str(sys.argv[1]))        


    content2 = str(sys.argv[2])
    pos2 = content2.rfind(".")
    postfix2 = content2[pos2+1:pos2+6]
    print(postfix2)
    if (str(postfix2) == "pfreq"):
        FrequencyArrayC, KeyFreqDictC = read_plaintext(str(sys.argv[2]))
    elif (str(postfix2) == "cfreq"):
        FrequencyArrayC, KeyFreqDictC = read_ciphertext(str(sys.argv[2])) 
    
    sumFrequencyArrayP = sum(FrequencyArrayP)
    sumFrequencyArrayC = sum(FrequencyArrayC)
    lenFrequencyArrayP = len(FrequencyArrayP)
    lenFrequencyArrayC = len(FrequencyArrayC)

    print("----------------Finish Reading Data------------")
    print("The maximum count of plaintext chunks: " + str(max(FrequencyArrayP)))
    print("The amount of unique plaintext chunks: " + str(lenFrequencyArrayP))
    print("Total Logical Plaintext Chunks: " + str(sumFrequencyArrayP))
    print("The maximum count of ciphertext chunks: " + str(max(FrequencyArrayC)))
    print("The amount of unique ciphertext chunks: " + str(lenFrequencyArrayC))
    print("Total Logical Ciphertext Chunks: " + str(sumFrequencyArrayC))

    FrequencyArrayP.sort()
    FrequencyArrayC.sort()
    print("First KLDivergence: %f" % (cal_KLD(FrequencyArrayP)))
    print("Second KLDivergence: %f" % (cal_KLD(FrequencyArrayC)))
    Saving = sumFrequencyArrayP - lenFrequencyArrayP
    Total = sumFrequencyArrayP
    rate = Saving / Total
    print("First Storage Saving: %f" % rate)
    Saving = sumFrequencyArrayC - lenFrequencyArrayC
    Total = sumFrequencyArrayC
    rate = Saving / Total
    print("Second Storage Saving: %f" % rate)
    print("----------------Storage Efficiency--------------")
    print("The amount of unique plaintext chunks: " + str(lenFrequencyArrayP))
    print("The amount of unique ciphertext chunks: " + str(lenFrequencyArrayC))
    print("Storage blowup rate: %f" % (1 + (lenFrequencyArrayC - lenFrequencyArrayP) / lenFrequencyArrayP))
    
    print("The maximum count of plaintext chunks: " + str(max(FrequencyArrayP)))
    print("The amount of unique plaintext chunks: " + str(lenFrequencyArrayP))
    print("Total Logical Plaintext Chunks: " + str(sumFrequencyArrayP))
    print("The maximum count of ciphertext chunks: " + str(max(FrequencyArrayC)))
    print("The amount of unique ciphertext chunks: " + str(lenFrequencyArrayC))
    print("Total Logical Ciphertext Chunks: " + str(sumFrequencyArrayC))
