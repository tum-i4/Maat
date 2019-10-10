#!/usr/bin/python

from Maat.utils.graphics import *
from Maat.shared.constants import *
from Maat.conf.config import *
from Maat.utils.misc import *

from numpy import mean, median, std
import matplotlib.pyplot as plt
from sklearn.metrics import *
import numpy as np

import glob, os, zipfile, random, subprocess
import pickle
from sklearn.tree import export_graphviz

def getAgeDistribution(datasetDir, vtReportsDir, generateHistogram=False, histogramTitle="testhistogram"):
    """
    Retrieves the first_seen date for apps in a dataset and returns a distribution of years
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDir: The directory containing the VirusTotal scan reports (needed for "first_seen")
    :type vtReportsDir: str
    :param includeFirstSeen: Whether to include the "first_seen" data in the results/graphs
    :type includeFirstSeen: bool
    :param generateHistogram: Whether to plot the results as a histogram
    :type generateHistogram: bool
    :param histogramTitle: The name to give to the generated histogram
    :type histogramTitle: str
    :return: A dict containing the age and (optionally) another dict for the first_seen dates and two str's for the generated histograms
    """
    try:
        firstSeenDist = {}
        pdfFile, pgfFile = "", ""
        # Retrieve the reports
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        for app in allApps:
            if VERBOSE == "ON":
                prettyPrint("Processing \"%s\", #%s out of %s" % (app, allApps.index(app), len(allApps)), "debug")

            key = app[app.rfind("/")+1:].replace(".apk", "")
            report = eval(open("%s/%s.report" % (vtReportsDir, key)).read())
            first_seen = report["first_seen"][:report["first_seen"].find(" ")]
            if first_seen.find("1980") != -1:
                continue

            year = first_seen.split('-')[0]
            if not year in firstSeenDist.keys():
                firstSeenDist[year] = 1.0
            else:
                firstSeenDist[year] += 1.0
        # Print the results
        years = firstSeenDist.keys()
        years.sort()
        for y in years:
            prettyPrint("Apps seen in %s = %s" % (y, firstSeenDist[y]), "output")

        # Visualize as histogram
        if generateHistogram:
            x = years
            y_pos = np.arange(len(years))
            y = [firstSeenDist[year] for year in years]
            plt.bar(y_pos, y, align='center', color='#8c8c8c', alpha=0.7)
            plt.xticks(y_pos, x)
            plt.grid(axis='y', alpha=0.75)
            plt.xlabel('"first_seen" in Years')
            plt.ylabel('Count of Apps')
            plt.ylim(ymax=ceilValue(max(firstSeenDist.values())))
            plt.show()
            plt.savefig("Histogram_%s.pdf" % histogramTitle)
            plt.savefig("Histogram_%s.pgf" % histogramTitle)


    except Exception as e:
        prettyPrintError(e)
        return {}, "", ""

    return firstSeenDist, "Histogram_%s.pdf" % histogramTitle, "Histogram_%s.pgf" % histogramTitle

def getPositivesDeltas(datasetDir, vtReportsDirs):
    """
    Calculates the mean and median of positives delta of apps in a dataset over a period of time
    :param datasetDir: The directory containing the APK archives of the apps in the dataset
    :type datasetDir: str
    :param vtReportsDirs: The directories containing the VirusTotal scan reports of apps in the dataset
    :type vtReportsDirs: str or list
    :return: Three floats depicting the mean, median, and standard deviation of positives delta
    """
    try:
        mean, median, stdev = 0.0, 0.0, 0.0
        # Retrieve the list of directories
        vtDirs = vtReportsDirs if type(vtReportsDirs) == list else glob.glob(vtReportsDirs)
        # Retrieve and iterate over the apps
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}, {}

        allDeltas = {}
        for app in allApps:
            key = app[app.rfind("/")+1:].replace(".apk", "")
            prettyPrint("Processing \"%s\", #%s out of %s" % (key, allApps.index(app)+1, len(allApps)), "debug")
            for vtDir in vtDirs:
                if os.path.exists("%s/%s.report" % (vtDir, key)):
                    report = eval(open("%s/%s.report" % (vtDir, key)).read())
                    if "additional_info" in report.keys():
                        if "positives_delta" in report["additional_info"].keys():
                            if not key in allDeltas.keys():
                                allDeltas[key] = []

                            allDeltas[key].append(report["additional_info"]["positives_delta"])

        allMeans, allMedians, allstds = [], [], []
        for app in allDeltas:
            allMeans.append(mean(allDeltas[app]))
            allMedians.append(median(allDeltas[app]))
            allstds.append(std(allDeltas[app]))

        # TODO: Calculate the overall mean, median, and stdev

    except Exception as e:
        prettyPrintError(e)
        return 0.0, 0.0, 0.0

    return mean, median, stdev


def plotDatasetsFirstSeen(plotBars=True, plotLines=True):
    """
    Plots a bar chart of the yearly distribution of apps in all our datasets according to the "first_seen" attribute
    """
    try:
        # Pre-calculated distrubtions for AMD, GPlay, AndroZoo'19, Manual 100, and Piggybacking
        amd_counts = [1.0, 8.0, 248.0, 2949.0, 9299.0, 7365.0, 3059.0, 1623.0, 0, 1.0, 0]
        gplay_counts = [0, 0, 26.0, 587.0, 1654.0, 5453.0, 2933.0, 6295.0, 3231.0, 7946.0, 1898.0]
        malware_2019_counts = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6173.0]
        manual_counts = [0, 0, 0, 6.0, 9.0, 25.0, 12.0, 30.0, 7.0, 11.0, 0]
        piggybacking_counts = [0, 14.0, 140.0, 510.0, 1168.0, 922.0, 0, 0, 0, 0, 0]

        # Miscellaneous information about the figure
        fig, ax = plt.subplots()
        all_years = ['2009', '2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019']
        index = np.arange(len(all_years))
        bar_width = 0.35
        opacity = 0.8
        # Build the data
        if plotBars:
            amd_rects = plt.bar(index, amd_counts, bar_width, alpha=opacity, color='#ff4136', label='AMD')
            gplay_rects = plt.bar(index, gplay_counts, bar_width, alpha=opacity, color='#3d9970', label='GPlay')
            malware_2019_rects = plt.bar(index, malware_2019_counts, bar_width, alpha=opacity, color='#ff851b', label='AndroZoo\'19')
            manual_rects = plt.bar(index, manual_counts, bar_width, alpha=opacity, color='#6baed6', label='Manual 100')
            piggybacking_rects = plt.bar(index, piggybacking_counts, bar_width, alpha=opacity, color='#808389', label='Piggybacking')
   
        if plotLines and not plotBars:
            ax.plot(index, amd_counts, color='#ff4136', marker='o', alpha=opacity, label='AMD') 
            ax.plot(index, gplay_counts, color='#3d9970', marker='^', alpha=opacity, label='GPlay')
            ax.plot(index, malware_2019_counts, color='#ff851b', marker='s', alpha=opacity, label='AndroZoo\'19')
            ax.plot(index, manual_counts, color='#6baed6', marker='+', alpha=opacity, label='Manual 100')
            ax.plot(index, piggybacking_counts, color='#808389', marker='x', alpha=opacity, label='Piggybacking')
       
        if plotLines and plotBars: 
            ax.plot(index, amd_counts, color='#ff4136', marker='o', alpha=opacity) 
            ax.plot(index, gplay_counts, color='#3d9970', marker='^', alpha=opacity)
            ax.plot(index, malware_2019_counts, color='#ff851b', marker='s', alpha=opacity)
            ax.plot(index, manual_counts, color='#6baed6', marker='+', alpha=opacity)
            ax.plot(index, piggybacking_counts, color='#808389', marker='x', alpha=opacity)
 

        # Set the labels' captions 
        plt.xlabel('"first_seen" by Years')
        plt.ylabel('Counts of Apps')
        plt.xticks(index + bar_width, tuple(all_years), rotation=45)
        plt.legend()
        plt.tight_layout()
        #plt.show()
        if plotLines and plotBars:
            title = "Lines_Bars"
        elif plotLines and not plotBars:
            title = "Lines"
        elif not plotLines and plotBars:
            title = "Bars"

        plt.savefig("%s_first_seen_all.pdf" % title)
        plt.savefit("%s_first_seen_all.pgf" % title)

    except Exception as e:
        prettyPrintError(e)
        return False

    return True


def visualizeTreesInForests(clf, features, numTrees=1, whichTrees="random", treeTitle=""):
    """
    Visualizes trees in a random forest classifiers
    :param clf: The path to the classifier or the classfier object itself
    :type clf: str or sklearn.ensemble.forest.RandomForestClassifier
    :param features: The list of features or the path to a file containing features (ordered) to use in visualizing the tree
    :type features: str or list
    :param numTrees: The number of trees to visualize (default: 1)
    :type numTrees: int
    :param whichTrees: The technique used to choose the trees to visualize (default: random vs. order == from the beginning).
    :type whichTrees: str
    :param treeTitle: The title(s) to give to the visualized tree(s)
    :type treeTitle: str
    :return: A boolean depicting the success/failure of the operation
    """
    try:
        # Load classifier
        clf = pickle.loads(open(clf).read()) if type(clf) == str else clf
        if not clf:
            prettyPrint("Could not load a classifier", "error")
            return False
        # Load features
        features = eval(open(features).read()) if type(features) == str else features
        if len(features) != clf.n_features_:
            prettyPrint("The dimensionality of the loaded features does not match that of the loaded classifier", "error")
            return False
        
        # Visualize trees
        for index in range(numTrees):
            treeIndex = random.randint(0, clf.n_estimators - 1) if whichTrees == "random" else clf.estimators_[index % clf.n_estimators]
            tTitle = "tree_%s" % treeIndex if treeTitle == "" else "tree_%s_%s" % (treeIndex, treeTitle.lower().replace(" ", "_"))
            prettyPrint("Visualizing tree \"%s.dot\"" % treeTitle)
            export_graphviz(clf.estimators_[treeIndex], out_file='%s.dot' % tTitle, feature_names=features, class_names=["Benign", "Malicious"], rounded=True, proportion=False, filled=True) 
            prettyPrint("Saving dot tree as PDF")
            #subprocess.call(['dot', '-Tpng', '%s.dot' % treeTitle, '-o', '%s.png' % treeTitle, '-Gdpi=600'])
            subprocess.call(['dot', '-Tpdf', '%s.dot' % tTitle, '-o', '%s.pdf' % tTitle, '-Gdpi=600'])
            subprocess.call(['rm', '%s.dot' % tTitle])


    except Exception as e:
        prettyPrintError(e)
        return False

    return True

