#!/usr/bin/python

from Maat.utils.graphics import *
from Maat.shared.constants import *
from Maat.conf.config import *
from Maat.utils.misc import *

from numpy import mean, median, std
import matplotlib.pyplot as plt
import numpy as np
import matplotlib
from matplotlib.backends.backend_pgf import FigureCanvasPgf
matplotlib.backend_bases.register_backend('pdf', FigureCanvasPgf)

def getCompleteness(datasetDir, vtReportsDir):
    """
    Calculates the completeness of all VirusTotal scanners at one point in time
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDir: The directory containing the VirusTotal reports
    :type vtReportsDir: str
    :return: A dict containing the completeness of all VirusTotal scanners
    """
    try:
        completeness = {}
        # Populate the dictionary with scanners
        for scanner in all_scanners:
            completeness[scanner] = []

        # Retrieve and iterate over the apps
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}

        for app in allApps:
            if VERBOSE == "ON":
                prettyPrint("Processing \"%s\", #%s out of %s" % (app, allApps.index(app), len(allApps)), "debug")

            key = app[app.rfind("/")+1:].replace(".apk", "")
            if os.path.exists("%s/%s.report" % (vtReportsDir, key)):
               report = eval(open("%s/%s.report" % (vtReportsDir, key)).read())
               for scanner in completeness:
                   if scanner in report["scans"].keys():
                       completeness[scanner].append(1.0)
                   
    except Exception as e:
        prettyPrintError(e)
        return {}

    return completeness

def getCompletenessOverTime(datasetDir, vtReportsDirs, generateLinePlot=False, plotScanners=[], useColors="ACM"):
    """
    Calculates the completeness of all VirusTotal scanners over a period of time
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDirs: The directories containing the VirusTotal reports (Should have any trace of date in the name e.g., vt_reports_2015)
    :type vtReportsDirs: list (OR) str
    :param generateLinePlot: Whether to generate a line plot depicting completeness over time for the top scanners (default: False)
    :type generateLinePlot: bool
    :param plotScanners: The list of scanners to plot. Plots all of list is empty (default)
    :type plotScanners: list
    :param useColors: Whether to use the ACMColors instead of randomly generating ones (default: ACM)
    :type useColors: str
    :return: A dict of completeness over time and a str of the path to the (not) generated plot
    """
    try:
        completeness = {}
        figurePath = ""
        # Populate the dictionary with scanners
        for scanner in all_scanners:
            completeness[scanner] = {}
 
        # Retrieve the list of directories
        vtDirs = vtReportsDirs if type(vtReportsDirs) == list else glob.glob(vtReportsDirs)
        # Retrieve and iterate over the apps
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}, ""
        
        # Retrieve the dates in the directories
        timestamps = []
        for vtDir in vtDirs:
            timestamps.append(vtDir[vtDir.rfind("_")+1:].replace("/", ""))
        timestamps.sort()
        for scanner in completeness:
            for t in timestamps:
                completeness[scanner][t] = 0.0

        # Now calculate the completeness
        for app in allApps:
            if VERBOSE == "ON":
                prettyPrint("Processing \"%s\", #%s out of %s" % (app, allApps.index(app), len(allApps)), "debug")

            key = app[app.rfind("/")+1:].replace(".apk", "")
            for vtDir in vtDirs:
                vtDirTimestamp = vtDir[vtDir.rfind("_")+1:].replace("/", "")
                if os.path.exists("%s/%s.report" % (vtDir, key)):
                   report = eval(open("%s/%s.report" % (vtDir, key)).read())
                   for scanner in completeness:
                       if scanner in report["scans"].keys():
                           completeness[scanner][vtDirTimestamp] += 1.0

        # Calculate completeness rates over time
        data = {}
        for scanner in all_scanners:
            if scanner in completeness.keys():
                tmp = []
                for timestamp in timestamps:
                    tmp.append(completeness[scanner][t] / float(len(allApps)))
                data[scanner] = tmp
                # Print results
                prettyPrint("Completeness of \"%s\"" % scanner, "output")
                for index in range(len(tmp)):
                    prettyPrint("At %s, completeness(%s) = %s" % (timestamps[index], scanner, tmp[index]), "output")

        # Plot results
        if generateLinePlot:
            opacity = 0.8
            plotScanners = all_scanners if plotScanners == [] else plotScanners
            for scanner in plotScanners:
                if scanner in data:
                    color = ACMColors[plotScanners.index(scanner) % len(ACMColors)]
                    line = ["-", "--"][random.randint(0, 1)]
                    plt.plot(timestamps, data[scanner], color=color, marker=getRandomMarker(), linestyle=line, alpha=opacity, label=scanner)

            plt.xlabel("Scan dates")
            plt.ylabel("Completeness")
            plt.xticks(rotation=45)
            plt.legend()
            plt.tight_layout()
            #plt.show()
            s = "all" if plotScanners == [] else len(plotScanners)
            figurePath = "Line_completeness_%s_scanners.pdf" % s
            plt.savefig(figurePath)
            plt.savefig(figurePath)
            plt.clf() # Clear the figure


    except Exception as e:
        prettyPrintError(e)
        return {}, ""

    return completeness, figurePath

def getCorrectness(datasetDir, vtReportsDir, groundTruth):
    """
    Calculates the correctness of VirusTotal scanners at one point in time
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDir: The directory containing the VirusTotal reports
    :type vtReportsDir: str
    :param groundTruth: The ground truth to compare the scanners' verdict against
    :type groundTruth: dict
    :return: A dict containing the correctness of all VirusTotal scanners
    """
    try:
        correctness = {}
        totalScanned = {}
        # Populate the dictionary with scanners
        for scanner in all_scanners:
            correctness[scanner] = 0.0
            totalScanned[scanner] = 0.0

        # Retrieve and iterate over the apps
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}

        for app in allApps:
            if VERBOSE == "ON":
                prettyPrint("Processing \"%s\", #%s out of %s" % (app, allApps.index(app), len(allApps)), "debug")

            key = app[app.rfind("/")+1:].replace(".apk", "")
            if os.path.exists("%s/%s.report" % (vtReportsDir, key)):
               report = eval(open("%s/%s.report" % (vtReportsDir, key)).read())
               for scanner in correctness:
                   if scanner in report["scans"].keys():
                       scannerVerdict = 1.0 if report["scans"][scanner]["detected"] == True else 0.0
                       if key in groundTruth:
                           totalScanned[scanner] += 1.0
                           if groundTruth[key] == scannerVerdict:
                               correctness[scanner] += 1.0

        # Print the results
        for scanner in all_scanners:
            prettyPrint("As per \"%s\", correctness(%s)=%s" % (vtReportsDir[vtReportsDir.rfind("_")+1:], scanner, correctness[scanner]/totalScanned[scanner]), "output")

    except Exception as e:
        prettyPrintError(e)
        return {}

    return correctness

def getCorrectnessByType(datasetDir, vtReportsDir, groundTruth, hashToTypeMapping):
    """
    Calculates the correctness of VirusTotal scanners at one point in time and groups them by type
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDir: The directory containing the VirusTotal reports
    :type vtReportsDir: str
    :param groundTruth: The ground truth to compare the scanners' verdict against
    :type groundTruth: dict
    :param hashToTypeMapping: A structure mapping hashes of apps in the dataset to malware type
    :type hashToTypeMapping: dict
    :return: A dict containing the correctness of all VirusTotal scanners grouped by malware type
    """
    try:
        correctness = {}
        totalScanned = {}
        # Populate the dictionary with scanners
        for scanner in all_scanners:
            correctness[scanner] = {}
            totalScanned[scanner] = {}
            for typ in amd_types:
                correctness[scanner][typ] = 0.0
                totalScanned[scanner][typ] = 0.0

        # Retrieve and iterate over the apps
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}

        for app in allApps:
            if VERBOSE == "ON":
                prettyPrint("Processing \"%s\", #%s out of %s" % (app, allApps.index(app), len(allApps)), "debug")

            key = app[app.rfind("/")+1:].replace(".apk", "")
            if os.path.exists("%s/%s.report" % (vtReportsDir, key)):
               report = eval(open("%s/%s.report" % (vtReportsDir, key)).read())
               for scanner in correctness:
                   if scanner in report["scans"].keys():
                       scannerVerdict = 1.0 if report["scans"][scanner]["detected"] == True else 0.0
                       if key in groundTruth:
                           # Get the malware type from the mapping
                           try:
                               malwareType = hashToTypeMapping[key]
                               totalScanned[scanner][malwareType] += 1.0
                               if groundTruth[key] == scannerVerdict:
                                   correctness[scanner][malwareType] += 1.0
                           except KeyError as ke:
                               continue

        # Print the results
        for scanner in all_scanners:
            prettyPrint("Correctness results for \"%s\" as per %s" % (scanner, vtReportsDir[vtReportsDir.rfind("_")+1:]), "output")
            c, t = 0.0, 0.0
            for malwareType in amd_types:
                if totalScanned[scanner][malwareType] > 0:
                    c += correctness[scanner][malwareType]
                    t += totalScanned[scanner][malwareType]
                    prettyPrint("%s: correctness(%s)=%s" % (malwareType, scanner, correctness[scanner][malwareType]/totalScanned[scanner][malwareType]), "output2")
                else:
                    prettyPrint("%s: correctness(%s)=0.0" % (malwareType, scanner), "output2")

            if t > 0.0:
                prettyPrint("Overall correctness(%s) = %s" % (scanner, round(c/t, 2)), "output2")

    except Exception as e:
        prettyPrintError(e)
        return {}

    return correctness

def getCorrectnessOverTime(datasetDir, vtReportsDirs, groundTruth, generateLinePlot=False, plotScanners=[], useColors="ACM"):
    """
    Calculates the correctness of all VirusTotal scanners over a period of time
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDirs: The directories containing the VirusTotal reports (Should have any trace of date in the name e.g., vt_reports_2015)
    :type vtReportsDirs: list (OR) str
    :param groundTruth: The ground truth to compare the scanners' verdict against
    :type groundTruth: dict
    :param generateLinePlot: Whether to generate a line plot depicting completeness over time for the top scanners (default: False)
    :type generateLinePlot: bool
    :param plotScanners: The list of scanners to plot. Plots all of list is empty (default)
    :type plotScanners: list
    :param useColors: The colors to use in generating the line plot (default: ACM = ACMColors, else random)
    :type useColors: str
    :return: Two dicts containing all correctly classified apps and a summary of correctness rates (AND) a str of the path to the (not) generated plot
    """
    try:
        correctness = {}
        totalScanned = {}
        figurePath = ""
        # Retrieve the list of directories
        vtDirs = vtReportsDirs if type(vtReportsDirs) == list else glob.glob(vtReportsDirs)
        # Retrieve and iterate over the apps
 
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}, ""

        # Retrieve the dates in the directories
        timestamps = []
        for vtDir in vtDirs:
            timestamps.append(vtDir[vtDir.rfind("_")+1:].replace("/", ""))
        timestamps.sort()

        # Populate the dictionary with scanners
        for scanner in all_scanners:
            correctness[scanner] = {}
            totalScanned[scanner] = {}
            for t in timestamps:
                correctness[scanner][t] = 0.0
                totalScanned[scanner][t] = 0.0

        for app in allApps:
            if VERBOSE == "ON":
                prettyPrint("Processing \"%s\", #%s out of %s" % (app, allApps.index(app), len(allApps)), "debug")

            key = app[app.rfind("/")+1:].replace(".apk", "")
            for vtDir in vtDirs:
                vtDirTimestamp = vtDir[vtDir.rfind("_")+1:].replace("/", "")
                if os.path.exists("%s/%s.report" % (vtDir, key)):
                   report = eval(open("%s/%s.report" % (vtDir, key)).read())
                   for scanner in correctness:
                       if scanner in report["scans"].keys():
                           scannerVerdict = 1.0 if report["scans"][scanner]["detected"] == True else 0.0
                           if key in groundTruth:
                               # Get the malware type from the mapping
                               totalScanned[scanner][vtDirTimestamp] += 1.0
                               if groundTruth[key] == scannerVerdict:
                                   correctness[scanner][vtDirTimestamp] += 1.0

        # Calculate correctess rates over time
        data = {}
        for scanner in all_scanners:
            if scanner in correctness.keys():
                tmp = []
                for timestamp in timestamps:
                    if totalScanned[scanner][timestamp] > 0.0:
                        tmp.append(correctness[scanner][timestamp] / totalScanned[scanner][timestamp])
                    else:
                        tmp.append(0.0)
                data[scanner] = tmp
                # Print results
                prettyPrint("Correctness of \"%s\"" % scanner, "info2")
                for index in range(len(tmp)):
                    prettyPrint("At %s, correctness(%s) = %s" % (timestamps[index], scanner, tmp[index]), "output")

        # Plot results
        if generateLinePlot:
            opacity = 0.8
            plotScanners = all_scanners if plotScanners == [] else plotScanners
            for scanner in plotScanners:
                if scanner in data:
                    color = ACMColors[plotScanners.index(scanner) % len(ACMColors)] if useColors == "ACM" else getRandomHexColor()
                    line = ["-", "--"][random.randint(0, 1)] # vs. getRandomLineStyle()
                    plt.plot(timestamps, data[scanner], color=color, marker=getRandomMarker(), linestyle=line, alpha=opacity, label=scanner)

            plt.xlabel("Scan dates")
            plt.ylabel("Correctness")
            plt.xticks(rotation=45)
            plt.legend()
            plt.tight_layout()
            #plt.show()
            s = "all" if plotScanners == [] else len(plotScanners)
            figurePath = "Line_correctness_%s_scanners" % s
            plt.savefig("./%s.pdf" % figurePath)
            plt.savefig("./%s.pgf" % figurePath)
            plt.clf() # Clear the figure


    except Exception as e:
        prettyPrintError(e)
        return {}, {}, ""

    return correctness, data, figurePath

def getMostCorrectScannersOverTime(datasetDir, vtReportsDirs, groundTruth, averageCorrectness=0.9, generateLinePlot=False, plotScanners=[]):
    """
    Calculates the correctness of all VirusTotal scanners over a period of time
    :param datasetDir: The directory containing the APK archives of the dataset
    :type datasetDir: str
    :param vtReportsDirs: The directories containing the VirusTotal reports (Should have any trace of date in the name e.g., vt_reports_2015)
    :type vtReportsDirs: list (OR) str
    :param groundTruth: The ground truth to compare the scanners' verdict against
    :type groundTruth: dict
    :param averageCorrectness: The average correctness to consider when choosing a scanner (default: 0.9)
    :type averageCorrectness: float
    :param generateLinePlot: Whether to generate a line plot depicting completeness over time for the top scanners (default: False)
    :type generateLinePlot: bool
    :param plotScanners: The list of scanners to plot. Plots all of list is empty (default)
    :type plotScanners: list
    :return: A list of str's depicting the scanners that have average correctness of more than averageCorrectness
    """
    try:
        topcorrect = []
        if VERBOSE == "ON":
            prettyPrint("Getting correctness of all scanners", "debug")

        correctness, summary, figurePath = getCorrectnessOverTime(datasetDir, vtReportsDirs, groundTruth, generateLinePlot, plotScanners)
        if len(correctness) < 1:
             prettyPrint("Could not retrieve correct scanners", "warning")
             return {}

        # Iterate over the scanners and retrieve the most correct scanners 
        for scanner in summary:
            if mean(summary[scanner]) >= averageCorrectness:
                prettyPrint("Adding scanner \"%s\" to list of top correct scanners" % scanner)
                topcorrect.append(scanner)

    except Exception as e:
        prettyPrintError(e)
        return {}

    return topcorrect
