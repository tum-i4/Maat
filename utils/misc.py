#!/usr/bin/python

import random, string, os, glob, subprocess, time
from datetime import datetime
from zipfile import ZipFile
import Levenshtein

matplotlib_markers = ['.', ',', 'o', 'v', '^', '<', '>', '1', '2', '3', '4', 's', 'p', '*', 'h', 'H', '+', 'x', 'D', 'd', '|', '_']
matplotlib_lines = ['-', '--', '-.', ':']


def averageList(inputList, roundDigits=2):
   return round(float(sum(inputList))/float(len(inputList)), roundDigits)

def ceilValue(maxValue):
    for i in range(10):
        if maxValue < pow(10, i):
            return pow(10, i)

    return maxValue

def checkRoot():
    if os.getuid() != 0:
        return False
    else:
        return True

def getClassesDEX(input_zip):
    input_zip=ZipFile(input_zip)
    for name in input_zip.namelist():
        if name.find("classes.dex") != -1:
            #print "Found it chief: %s" % name
            return input_zip.read(name)

    return ""

def stringRatio(str1, str2):
    if str1 is None or str2 is None:
        return 0.0
    elif len(str1) < 1 or len(str2) < 1:
        return 0.0
    elif not isinstance(str1, str) and not isinstance(str1, unicode):
        return 0.0
    elif not isinstance(str2, str) and not isinstance(str2, unicode):
        return 0.0
    else:
        str1, str2 = unicode(str1), unicode(str2) # Avoid differences in types (e.g., str vs. unicode)
        return float(len(str1+str2) - Levenshtein.distance(str1, str2))/len(str1+str2)

def subfinder(theList, thePattern):
    stride = len(thePattern)
    for index in range(len(theList)):              
        if theList[index:index+stride] == thePattern:                                          
            return True

def listsRatio(list1, list2):
    if len(list1) == 0 or len(list2) == 0:
        return 0.0

    intersection = len(list(set(list1).intersection(list2)))
    #print(list(set(list1).intersection(list2)))
    union = (len(list1) + len(list2)) - intersection
    return float(intersection / union)

def flip(p):
    return 'YES' if random.random() < p else 'NO'

def getRandomNumber(length=8):
    return ''.join(random.choice(string.digits) for i in range(length))

def getRandomAlphaNumeric(length=8):
    return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(length))

def getRandomMarker():
    return matplotlib_markers[random.randint(0, len(matplotlib_markers)-1)]

def getRandomLineStyle():
    return matplotlib_lines[random.randint(0, len(matplotlib_lines)-1)]

def getRandomMarkerAndLine():
    return getRandomMarker()+getRandomLineStyle()

def getRandomHexColor():
    return '#'+''.join(random.choice("0123456789abcdef") for i in range(6))


def getRandomString(length=8):
    return ''.join(random.choice(string.lowercase) for i in range(length))

def getTimestamp(includeDate=False):
    if includeDate:
        return "[%s]"%str(datetime.now())
    else:
        return "[%s]"%str(datetime.now()).split(" ")[1]

# Copied from the "googleplay_api" helpers.py
def sizeof_fmt(num):
    for x in ['bytes','KB','MB','GB','TB']:
        if num < 1024.0:
            return "%3.1f%s" % (num, x)
        num /= 1024.0

def sortDictByValue(d, reverse=False):
    sortedDict = []
    for key, value in sorted(d.iteritems(), key=lambda (k,v): (v,k), reverse=reverse):         
        sortedDict.append((key, value))

    return sortedDict

def specificity(ground_truth, predicted, classes=(1, 0)):
    if len(ground_truth) != len(predicted):
        return -1
    if not 0.0 in ground_truth:
        # Ground truth exclusively contains 1's
        return -1

    positive, negative = classes[0], classes[1]
    tp, tn, fp, fn = 0, 0, 0, 0
    for index in range(len(ground_truth)):
        if ground_truth[index] == negative and predicted[index] == negative:
            tn += 1
        elif ground_truth[index] == negative and predicted[index] == positive:
            fp += 1
        elif ground_truth[index] == positive and predicted[index] == negative:
            fn += 1
        else:
            tp += 1

    return float(tn)/(float(tn)+float(fp))
