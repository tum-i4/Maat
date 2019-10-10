#!/sr/bin/python

from Maat.utils.graphics import *
from Maat.shared.constants import *
from Maat.conf.config import *
from Maat.utils.misc import *
from Maat.visualization.visualize_data import *

import glob, os, re, time
from numpy import mean, median, std
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import numpy as np
import matplotlib
from matplotlib.backends.backend_pgf import FigureCanvasPgf
matplotlib.backend_bases.register_backend('pdf', FigureCanvasPgf)

def getTimeToStabilize(datasetDir, vtReportsDirs, familiesAndTypesMapping={}, stability="positives"):
    """
    Calculates the time taken by VirusTotal scanners to stabilize the detection rate of an app
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDirs: The directories containing the VirusTotal reports 
    :type vtReportsDirs: list or str
    :param familiesAndTypesMapping: A structure that maps apps to malware families and types
    :type familiesAndTypesMapping: dict
    :param stability: The metric to adopt upon checking the stability of an app's scan report (default: positives)
    :type stability: str
    :return: Two dicts containing the apps that stabilized and those that have not stabilized yet
    """
    try:
        # Retrieve the list of directories
        vtDirs = vtReportsDirs if type(vtReportsDirs) == list else glob.glob(vtReportsDirs)
        # Retrieve and iterate over the apps
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}, {}

        data = {}        
        for app in allApps:
           if VERBOSE == "ON":
               prettyPrint("Processing \"%s\", #%s out of %s" % (app, allApps.index(app), len(allApps)), "debug")

           key = app[app.rfind("/")+1:].replace(".apk", "")
           previousRatio = 0.0
           for vtDir in vtDirs:
               if not os.path.exists("%s/%s.report" % (vtDir, key)):
                   continue

               report = eval(open("%s/%s.report" % (vtDir, key)).read())
               if "additional_info" in report.keys():
                   if stability == "positives":
                       if "positives_delta" in report["additional_info"].keys():
                           if report["additional_info"]["positives_delta"] == 0:
                               # Get the date difference
                               first_seen = datetime.strptime(report["first_seen"], "%Y-%m-%d %H:%M:%S")
                               scan_date = datetime.strptime(report["scan_date"], "%Y-%m-%d %H:%M:%S")
                               age = (scan_date - first_seen).days / 360.0
                               if not key in data.keys():
                                   typ = familiesAndTypesMapping[key][1] if len(familiesAndTypesMapping) > 0 else "N/A"
                                   data[key] = (key, typ, age, report["first_seen"], report["scan_date"], report["positives"], report["total"])
                   else:
                       # Check whether the positives/total changed from last time
                       currentRatio = report["positives"]/float(report["total"])
                       if previousRatio != 0.0 and currentRatio == previousRatio: 
                           # Get the date difference
                           first_seen = datetime.strptime(report["first_seen"], "%Y-%m-%d %H:%M:%S")
                           scan_date = datetime.strptime(report["scan_date"], "%Y-%m-%d %H:%M:%S")
                           age = (scan_date - first_seen).days / 360.0
                           if not key in data.keys():
                               typ = familiesAndTypesMapping[key][1] if len(familiesAndTypesMapping) > 0 else "N/A"
                               data[key] = (key, typ, age, report["first_seen"], report["scan_date"], report["positives"], report["total"])
                           
                       previousRatio = currentRatio
        # Print results
        meanAge, medianAge = mean([data[key][2] for key in data]), median([data[key][2] for key in data])     
        prettyPrint("In total, %s apps have stabilized within a mean and median of %s and %s years" % (len(data), meanAge, medianAge), "info2")
        if len(familiesAndTypesMapping) > 0:
            for malwareType in amd_types:
                prettyPrint("Out of %s apps of type \"%s\", the mean and median age to stabilize are %s and %s years" % (len([data[key] for key in data if data[key][1] == malwareType]), malwareType, mean([data[key][2] for key in data if data[key][1] == malwareType]), median([data[key][2] for key in data if data[key][1] == malwareType])), "output")
   
        # Apps that didn't stabilize
        prettyPrint("Gathering information about unstable apps")
        anti_data = {}
        for app in allApps:
            key = app[app.rfind("/")+1:].replace(".apk", "")
            if not key in data.keys():
                report = eval(open("%s/%s.report" % (vtDirs[0], key)).read()) # Any report dir should work
                first_seen = datetime.strptime(report["first_seen"], "%Y-%m-%d %H:%M:%S")
                today = datetime.fromtimestamp(time.time())
                age = (today - first_seen).days / 360.0
                typ = familiesAndTypesMapping[key][1] if len(familiesAndTypesMapping) > 0 else "N/A"
                anti_data[key] = (key, typ, age, report["first_seen"], report["scan_date"], report["positives"], report["total"])                    

        # Print results
        meanAge, medianAge = mean([anti_data[key][2] for key in anti_data]), median([anti_data[key][2] for key in anti_data])
        prettyPrint("In total, %s apps have NOT stabilized within a mean and median of %s and %s years" % (len(anti_data), meanAge, medianAge), "info2")
        if len(familiesAndTypesMapping) > 0:
            for malwareType in amd_types:
                prettyPrint("Out of %s apps of type \"%s\", the mean and median age are %s and %s years" % (len([anti_data[key] for key in anti_data if anti_data[key][1] == malwareType]), malwareType, mean([anti_data[key][2] for key in anti_data if anti_data[key][1] == malwareType]), median([anti_data[key][2] for key in anti_data if anti_data[key][1] == malwareType])), "output")

    except Exception as e:
        prettyPrintError(e)
        return {}, {}

    return data, anti_data 


def getTimeToDetect(datasetDir, vtReportsDirs, detectCorrectly=True, familiesAndTypesMapping={}, groundTruth={}, scanners=[]):
    """
    Calculates the amount of time it takes VirusTotal classifiers to detect malicious apps
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDirs: The directories containing the VirusTotal scan reports
    :type vtReportsDirs: list or str
    :param detectCorrectly: Whether to solely focus on correct detections of malware versus any sort of labels (default: True)
    :type detectCorrectly: bool
    :param familiesAndTypesMapping: A structure that maps apps to malware families and types
    :type familiesAndTypesMapping: dict
    :param groundTruth: The ground truth labels of the apps in the dataset
    :type groundTruth: dict
    :param scanners: The scanners to focus on upon calculating the time to detect
    :type scanners: list
    :return: A dict containing the details about the apps every scanner detected in the dataset
    """
    try:
        timeToDetect = {}
        scanners = all_scanners if scanners == [] else scanners
        for scanner in scanners:
            timeToDetect[scanner] = {}

        # Retrieve the list of directories
        vtDirs = vtReportsDirs if type(vtReportsDirs) == list else glob.glob(vtReportsDirs)
        # Retrieve and iterate over the apps
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}, ""

        data = {}
        for app in allApps:
           if VERBOSE == "ON":
               prettyPrint("Processing \"%s\", #%s out of %s" % (app, allApps.index(app), len(allApps)), "debug")

           key = app[app.rfind("/")+1:].replace(".apk", "")
           for vtDir in vtReportsDirs:
               if not os.path.exists("%s/%s.report" % (vtDir, key)):
                   continue

               report = eval(open("%s/%s.report" % (vtDir, key)).read())
               for scanner in timeToDetect:
                   if scanner in report["scans"].keys():
                       if not detectCorrectly:
                           if "first_seen" in report.keys() and "scan_date" in report.keys():
                               first_seen = datetime.strptime(report["first_seen"], "%Y-%m-%d %H:%M:%S")
                               scan_date = datetime.strptime(report["scan_date"], "%Y-%m-%d %H:%M:%S")
                               age = (scan_date - first_seen).days / 360.0
                               typ = "N/A" if familiesAndTypesMapping == {} else familiesAndTypesMapping[key][1]
                               if not key in timeToDetect[scanner].keys():
                                   timeToDetect[scanner][key] = (key, typ, age, report["positives"], report["total"])
                       else:
                           gt = groundTruth[key]
                           if (report["scans"][scanner]["detected"] == True and gt == 1.0) or (report["scans"][scanner]["detected"] == False and gt == 0.0):
                               if "first_seen" in report.keys() and "scan_date" in report.keys():
                                   first_seen = datetime.strptime(report["first_seen"], "%Y-%m-%d %H:%M:%S")
                                   scan_date = datetime.strptime(report["scan_date"], "%Y-%m-%d %H:%M:%S")
                                   age = (scan_date - first_seen).days / 360.0
                                   typ = "N/A" if familiesAndTypesMapping == {} else familiesAndTypesMapping[key][1]
                                   if not key in timeToDetect.keys():
                                       timeToDetect[scanner][key] = (key, typ, age, report["positives"], report["total"])

        # Print summary of results
        prettyPrint("Data about scanners", "info2")
        for scanner in scanners:
            prettyPrint("It takes \"%s\" a mean and median of %s and %s years to detect %s out of %s apps" % (scanner, mean([timeToDetect[scanner][key][2] for key in timeToDetect[scanner]]), median([timeToDetect[scanner][key][2] for key in timeToDetect[scanner]]), len(timeToDetect[scanner]), len(allApps)), "output")
            if familiesAndTypesMapping != {}:
                tmp = {}
                for typ in amd_types:
                    tmp[typ] = []
                for entry in timeToDetect[scanner]:
                    tmp[timeToDetect[scanner][entry][1]].append(timeToDetect[scanner][entry][2])
                # More details about scanner's performance on malware types
                for typ in amd_types:
                    prettyPrint("It takes \"%s\" a mean and median of %s and %s years to detect \"%s\" apps" % (scanner, mean(tmp[typ]), median(tmp[typ]), typ))

    except Exception as e:
        prettyPrintError(e)
        return {}

    return timeToDetect

def getChangeInPositives(datasetDir, vtReportsDirs, plotChanges=False, figureTitle="test"):
    """
    Calculates the change in the number of positives over time in a dataset
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDirs: The directories containing the VirusTotal scan reports
    :type vtReportsDirs: list or str
    :param plotChanges: Whether to plot the changes in positives/total over time as a line plot
    :type plotChange: boolean
    :param figureTitle: A title to give the figure
    :type figureTitle: str
    :return: A dict with of positives per app over time
    """
    try:
        changes = {}
        positives, totals = [], []
        # Retrieve the list of directories
        vtDirs = vtReportsDirs if type(vtReportsDirs) == list else glob.glob(vtReportsDirs)
        # Retrieve and iterate over the apps
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}

        data = {}
        for app in allApps:
           if VERBOSE == "ON":
               prettyPrint("Processing \"%s\", #%s out of %s" % (app, allApps.index(app), len(allApps)), "debug")

           key = app[app.rfind("/")+1:].replace(".apk", "")
           tmpPositives, tmpTotals = [], []
           for vtDir in vtReportsDirs:
               if not os.path.exists("%s/%s.report" % (vtDir, key)):
                   continue

               report = eval(open("%s/%s.report" % (vtDir, key)).read())
               if not key in changes:
                   changes[key] = [report["positives"]]
               else:
                   changes[key].append(report["positives"])

               tmpPositives.append(report["positives"])
               tmpTotals.append(report["total"])

           # Building a matrices of positives and totals:
           # Rows depict apps and columns depict points in time
           positives.append(tmpPositives)
           totals.append(tmpTotals)

        # Calculate changes in percentage
        for app in changes:
            try:
                percentages = [100 * (b - a) / a for a, b in zip(changes[app][::1], changes[app][1::1])]
                #if VERBOSE == "ON":
                #    prettyPrint("For app \"%s\" between %s and %s, the mean and median change in percentage of positives are %s and %s" % (app, vtReportsDirs[0], vtReportsDirs[-1], mean(percentages), median(percentages)), "debug")
            except ZeroDivisionError as zde:
                continue

        # Plot changes in positives?
        if plotChanges:
            # Prepare the data
            meanPositives = [mean(np.array(positives)[:,index]) for index in range(np.array(positives).shape[1])]
            medianPositives = [median(np.array(positives)[:,index]) for index in range(np.array(positives).shape[1])]
            meanTotals = [mean(np.array(totals)[:,index]) for index in range(np.array(totals).shape[1])]
            medianTotals = [median(np.array(totals)[:,index]) for index in range(np.array(totals).shape[1])]
            timestamps = []

            for vtDir in vtDirs:
                timestamps.append(vtDir[vtDir.rfind("_")+1:].replace("/", ""))
            timestamps.sort()
            # Build the figure
            opacity = 0.8
            plt.cla() # Clean up the plot 
            plt.plot(timestamps, meanPositives, color=getRandomHexColor(), marker=getRandomMarker(), linestyle=getRandomLineStyle(), alpha=opacity, label="Mean Positives")
            plt.plot(timestamps, medianPositives, color=getRandomHexColor(), marker=getRandomMarker(), linestyle=getRandomLineStyle(), alpha=opacity, label="Median Positives")
            plt.xlabel("Scan dates")
            plt.ylabel("Counts")
            plt.xticks(rotation=45)
            plt.legend()
            plt.tight_layout()
            figurePath = "Line_Positives_%s" % figureTitle
            plt.savefig("./%s.pdf" % figurePath)
            plt.savefig("./%s.pgf" % figurePath)
            plt.plot(timestamps, meanTotals, color=getRandomHexColor(), marker=getRandomMarker(), linestyle=getRandomLineStyle(), alpha=opacity, label="Mean Total")
            plt.plot(timestamps, medianTotals, color=getRandomHexColor(), marker=getRandomMarker(), linestyle=getRandomLineStyle(), alpha=opacity, label="Median Total")
            plt.legend()
            figurePath = "Line_Positives_Totals_%s" % figureTitle
            plt.savefig("./%s.pdf" % figurePath)
            plt.savefig("./%s.pgf" % figurePath)
            #plt.show()

    except Exception as e:
        prettyPrintError(e)
        return {}

    return changes


def getHesitantScanners(datasetDir, vtReportsDirs, groundTruth, hesitationPattern="", familiesAndTypesMapping={}):
    """
    Retrieves the VirusTotal scanners that change their minds vis-a-vis apps' labels
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDirs: The directories containing the VirusTotal scan reports
    :type vtReportsDirs: list or str
    :param groundTruth: The ground truth of the apps in the dataset
    :type groundTruth: dict
    :param hesitationPattern: The pattern to look for reflecting whether an app has been detected
    :type hesitationPattern: list of bool's
    :param familiesAndTypesMapping: A structure that maps apps to malware families and types
    :type familiesAndTypesMapping: dict
    :return: A dict containing the details about the scanners that change their minds
    """
    try:
        # Retrieve the list of directories
        vtDirs = vtReportsDirs if type(vtReportsDirs) == list else glob.glob(vtReportsDirs)
        # Retrieve and iterate over the apps
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}

        data = {} 
        totalScanned = {}
        for scanner in all_scanners:
            data[scanner] = {}
            totalScanned[scanner] = []

        for app in allApps:
            if VERBOSE == "ON":
                prettyPrint("Processing \"%s\", #%s out of %s" % (app, allApps.index(app), len(allApps)), "debug")

            key = app[app.rfind("/")+1:].replace(".apk", "")
            for vtDir in vtReportsDirs:
                if os.path.exists("%s/%s.report" % (vtDir, key)):
                    report = eval(open("%s/%s.report" % (vtDir, key)).read())

                    for scanner in all_scanners:
                        if scanner in report["scans"].keys():
                            if not app in totalScanned[scanner]:
                                totalScanned[scanner].append(app)

                            if key in data[scanner].keys():
                                data[scanner][key].append(report["scans"][scanner]["detected"])
                            else:
                                data[scanner][key] = [report["scans"][scanner]["detected"]]

        hesitants = {}
        correct = {}
        hesitationPattern = "T+F+T|F+T+F" if hesitationPattern == "" else hesitationPattern
        for scanner in all_scanners:
            prettyPrint("Processing scanner \"%s\"" % scanner)
            for app in data[scanner]:
                # Represent the sequence as that of T's and F's
                sequence = ""
                for verdict in data[scanner][app]:
                    if verdict:
                        sequence += "T"
                    else:
                        sequence += "F"

                # Check for existence of regex
                matches = re.findall(hesitationPattern, sequence)
                if len(matches) > 0:
                    if not scanner in hesitants.keys():                     
                        hesitants[scanner] = [app]
                    else:                                
                        hesitants[scanner].append(app) 

                    # Check whether the hesitation was to the correct labels
                    if groundTruth[app] == 1.0 and sequence[-1] == "T":
                        if not scanner in correct.keys():
                            correct[scanner] = [app]
                        else:
                            correct[scanner].append(app)
                    elif groundTruth[app] == 0.0 and sequence[-1] == "F":
                        if not scanner in correct.keys():
                            correct[scanner] = [app]
                        else:
                            correct[scanner].append(app)

            if scanner in hesitants.keys():
                prettyPrint("Scanner \"%s\" changed its verdict twice (once or more) on %s out of %s apps" % (scanner, len(hesitants[scanner]), len(totalScanned[scanner])), "info2")

        # Types causing hesitation
        if familiesAndTypesMapping != {}:
            for scanner in all_scanners:
                if scanner in hesitants.keys():
                    prettyPrint("Scanner: %s" % scanner, "info2")
                    types = []
                    for app in hesitants[scanner]:
                        types.append(familiesAndTypesMapping[app][1])

                    for t in amd_types:
                        if t in types:
                            prettyPrint("%s: %s" % (t, types.count(t)/float(len(types))), "output")

    except Exception as e:
        prettyPrintError(e)
        return {}, {}

    return hesitants, correct

def getStableToUnstableApps(datasetDir, vtReportsDir):
    """
    Retrieves the list of apps in a dataset that had positives_delta=0 before changing in more recent scans
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDir: The list of directories containing the VirusTotal scan reports or a pattern of their names
    :type vtReportsDir: list or str
    :return: A list of sha256 hashes of apps that suffered from this phenonmenon
    """
    try:
        # Retrieve the list of directories
        vtDirs = vtReportsDirs if type(vtReportsDirs) == list else glob.glob(vtReportsDirs)
        # Retrieve and iterate over the apps
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}

        tmpStable, stableToUnstable = [], []
        for app in allApps:
            key = a[a.rfind("/")+1:].replace(".apk", "")
            prettyPrint("Processing %s, #%s out of %s" % (key, amd.index(a), len(amd)))
            for d in vtDirs:
                if os.path.exists("%s/%s.report" % (d, key)):
                    report = eval(open("%s/%s.report" % (d, key)).read())
                    if "additional_info" in report.keys():
                        if "positives_delta" in report["additional_info"].keys():
                            if report["additional_info"]["positives_delta"] == 0:
                                if not key in tmpStable:
                                    prettyPrint("App \"%s\" had 0 positives_delta on %s" % (key, d), "debug")
                                    tmpStable.append(key)
                            else:
                                if key in tmpStable:
                                    prettyPrint("App \"%s\" now has positives_delta=%s on %s" % (key, report["additional_info"]["positives_delta"], d), "error")
                                    if not key in stableToUnstable:
                                        prettyPrint("Adding app \"%s\" to unstable list" % key, "info2")
                                        stableToUnstable.append(key)
                                        #tmpStable.remove(key)
    except Exception as e:
        prettyPrintError(e)
        return []

    return stableToUnstable

def getStableScanners(datasetDir, vtReportsDirs, scannersToConsider=[], stabilityThreshold=0.9):
    """
    Calculates the stability of VirusTotal scanners over a finite period of time
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDirs: The directories containing the VirusTotal reports of apps in the dataset
    :type vtReportsDirs: list or str
    :param scannersToConsider: The VirusTotal scanners to focus on during the analysis (default: [] = all scanners)
    :type scannersToConsider: list of str's
    :param stabilityThreshold: The minimum stability threshold for a scanner to be considered stable (default: 0.9)
    :type stabilityThreshold: float
    :return: A dict of stable scanners (keys: scanner names, values: list of sha256 hashes of stable apps
    """
    try:
        stable = {}
        # Retrieve the list of directories
        vtDirs = vtReportsDirs if type(vtReportsDirs) == list else glob.glob(vtReportsDirs)
        # Retrieve and iterate over the apps
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}

        scanners = scannersToConsider if len(scannersToConsider) > 0 else all_scanners
        for scanner in scanners:
            stable[scanner] = {} 

        for app in allApps:
            key = app[app.rfind("/")+1:].replace(".apk", "")
            if VERBOSE == "ON":
                prettyPrint("Processing \"%s\", #%s out of %s" % (key, allApps.index(app), len(allApps)), "debug")

            for vtDir in vtDirs:
                if os.path.exists("%s/%s.report" % (vtDir, key)):
                    report = eval(open("%s/%s.report" % (vtDir, key)).read())
                    for scanner in scanners:
                        if scanner in report["scans"].keys():
                            label = "T" if report["scans"][scanner]["detected"] else "F"

                            if not key in stable[scanner].keys():
                                stable[scanner][key] = []

                            stable[scanner][key].append(label)

        # Display results and calculate stability
        results = {}
        for scanner in scanners:
            results[scanner] = []
            prettyPrint("Results for scanner \"%s\"" % scanner, "output")
            tmp = []
            for app in stable[scanner]:
                stabilityScore = stable[scanner][app].count(max(stable[scanner][app]))/float(len(stable[scanner][app]))
                tmp.append(stabilityScore)
                if stabilityScore >= stabilityThreshold:
                    results[scanner].append(app)

            prettyPrint("The mean, median, and standard deviation stability score are %s, %s, and %s" % (mean(tmp), median(tmp), std(tmp)), "info2")
            

    except Exception as e:
        prettyPrintError(e)
        return {}

    return results

def plotPositivesOverTime(datasetDir, vtReportsDirs, hashToTypeMapping, plotTitle="", useColors="ACM"):
    """
    Plots the evolution of the number of scanners deeming an app as malicious over time (in monthly and yearly scales)
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDirs: The directories containing the VirusTotal reports of apps in the dataset
    :type vtReportsDirs: list or str
    :param hashToTypeMapping: A structure mapping hashes of apps in the dataset to malware type
    :type hashToTypeMapping: dict
    :param plotTitle: The title to give to the plot upon saving to disk
    :type plotTitle: str
    :param useColors: Whether to use ACMColors in the plots (default: ACM)
    :type useColors: str
    :return: A bool indicating the success of the plotting operations
    """
    try:
        # Retrieve the list of directories
        vtDirs = vtReportsDirs if type(vtReportsDirs) == list else glob.glob(vtReportsDirs)
        # Retrieve and iterate over the apps
        allApps = datasetDir if type(datasetDir) == list else glob.glob("%s/*.apk" % datasetDir)
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}

        # Identify the apps that have scan reports in ALL directories (longest history)
        appKeys = [app[app.rfind("/")+1:].replace(".apk", "") for app in allApps]
        available = {}
        if VERBOSE == "ON":
            prettyPrint("Retrieving the apps that have scan reports in all directories", "debug")

        for v in vtDirs:
            available[v] = []
            for key in appKeys:
                if os.path.exists("%s/%s.report" % (v, key)):
                    available[v].append(key)

        # Retrieve the intersection between all lists of apps
        commonApps = list(set.intersection(*[set(available[v]) for v in available]))
        if len(commonApps) < 1:
            prettyPrint("Unable to retrieve any common apps", "error")
            return ""

        prettyPrint("Successfully retrieved %s common apps" % len(commonApps))
        # Retrieve the history of each app
        positivesProgressMonth, positivesProgressYear = {}, {}
        for app in commonApps:
            prettyPrint("Processing app \"%s\", #%s out of %s" % (app, commonApps.index(app)+1, len(commonApps)))
            positivesProgressMonth[app] = {}
            positivesProgressYear[app] = {}
            for v in vtDirs:
                report = eval(open("%s/%s.report" % (v, app)).read())
                if "positives" in report.keys():
                    d = report["scan_date"]  
                    keyMonth = d[:d.rfind('-')]
                    keyYear =  d[:d.find('-')]
                    if not keyMonth in positivesProgressMonth[app].keys():
                        positivesProgressMonth[app][keyMonth] = []
                    if not keyYear in positivesProgressYear[app].keys():
                        positivesProgressYear[app][keyYear] = []

                    positivesProgressMonth[app][keyMonth].append(report["positives"])
                    positivesProgressYear[app][keyYear].append(report["positives"])
                       

        # Prepare data before plotting
        # 1. Get all available time points
        timePointsMonth = []
        timePointsYear = []
        for app in positivesProgressMonth:
            for point in positivesProgressMonth[app]: 
                if not point in timePointsMonth:
                    timePointsMonth.append(point)

        for app in positivesProgressYear:
            for point in positivesProgressYear[app]: 
                if not point in timePointsYear:
                    timePointsYear.append(point)

        timePointsMonth.sort()
        timePointsYear.sort()
        # 2. Gather positives and their medians per time point and malware type
        dataMonth, dataYear = {}, {}
        for malwareType in amd_types+["all"]:
            dataMonth[malwareType] = {}        
            dataYear[malwareType] = {}
            #for timePoint in timePoints:
            #    data[malwareType][timePoint] = []
 
        for app in positivesProgressMonth:
            appType = hashToTypeMapping[app] # Make sure the dict has the format d[app] = "type"
            for point in positivesProgressMonth[app]:
                if not point in dataMonth["all"].keys():
                    dataMonth["all"][point] = []

                if not point in dataMonth[appType].keys():
                    dataMonth[appType][point] = []

                dataMonth[appType][point] += positivesProgressMonth[app][point]
                dataMonth["all"][point] += positivesProgressMonth[app][point]
 
        for app in positivesProgressYear:
            appType = hashToTypeMapping[app] # Make sure the dict has the format d[app] = "type"
            for point in positivesProgressYear[app]:
                if not point in dataYear["all"].keys():
                    dataYear["all"][point] = []

                if not point in dataYear[appType].keys():
                    dataYear[appType][point] = []

                dataYear[appType][point] += positivesProgressYear[app][point]
                dataYear["all"][point] += positivesProgressYear[app][point]

        # 3. Take the medians and st. devs per type
        allXs = {malwareType: [] for malwareType in dataMonth.keys()}
        allYs = {malwareType: [] for malwareType in dataMonth.keys()}
        allSt = {malwareType: [] for malwareType in dataMonth.keys()}
        allBx = {malwareType: [] for malwareType in dataMonth.keys()}
        allXs_year = {malwareType: [] for malwareType in dataYear.keys()}
        allYs_year = {malwareType: [] for malwareType in dataYear.keys()}
        allSt_year = {malwareType: [] for malwareType in dataYear.keys()}
        allBx_year = {malwareType: [] for malwareType in dataYear.keys()}

        for malwareType in dataMonth:
            for timePoint in timePointsMonth:
                if timePoint in dataMonth[malwareType].keys():
                    allXs[malwareType].append(timePointsMonth.index(timePoint))
                    allYs[malwareType].append(median(dataMonth[malwareType][timePoint]))
                    allSt[malwareType].append(std(dataMonth[malwareType][timePoint]))
                    allBx[malwareType].append(dataMonth[malwareType][timePoint])

        # And again for year, yuck!!       
        for malwareType in dataYear:
            for timePoint in timePointsYear:
                if timePoint in dataYear[malwareType].keys():
                    allXs_year[malwareType].append(timePointsYear.index(timePoint))
                    allYs_year[malwareType].append(median(dataYear[malwareType][timePoint]))
                    allSt_year[malwareType].append(std(dataYear[malwareType][timePoint]))
                    allBx_year[malwareType].append(dataYear[malwareType][timePoint])

        # Now plot the figure
        # 1. First the medians figure
        plt.cla()
        opacity = 0.8
        types = amd_types + ["all"]
        markers = [getRandomMarker() for x in range(len(types))]
        lines = [["-", "--"][random.randint(0, 1)] for x in range(len(types))]
        for malwareType in types:
            color = ACMColors[types.index(malwareType) % len(ACMColors)] if useColors == "ACM" else getRandomHexColor()
            marker, line = markers[types.index(malwareType)], lines[types.index(malwareType)]
            if len(allXs[malwareType]) > 0:
                if malwareType == "all":
                    plt.plot(allXs[malwareType], allYs[malwareType], color="gray", marker=marker, linestyle="-", linewidth=4.0, alpha=opacity, label="All Types")
                else:
                    plt.plot(allXs[malwareType], allYs[malwareType], color=color, marker=marker, linestyle=line, alpha=opacity, label=malwareType)

        plt.xlabel("Scan Month")
        plt.ylabel("VirusTotal Positives")
        plt.xticks(range(len(timePointsMonth)), timePointsMonth, rotation=90, fontsize=5)
        plt.legend(loc='lower right', fontsize=8)
        plt.tight_layout()
        #plt.show()
        figurePath = "Positives_evolution_median_month" if plotTitle == "" else plotTitle
        plt.savefig("./%s.pdf" % figurePath)
        plt.savefig("./%s.pgf" % figurePath)

        # 2. The median of "all" + boxes and whiskers
        plt.cla()
        opacity = 0.8
        for malwareType in types:
            color = ACMColors[types.index(malwareType) % len(ACMColors)] if useColors == "ACM" else getRandomHexColor()
            marker, line = markers[types.index(malwareType)], lines[types.index(malwareType)]
            if len(allXs[malwareType]) > 0:
                if malwareType == "all":
                    plt.plot(allXs[malwareType], allYs[malwareType], color="gray", marker=marker, linestyle="-", linewidth=4.0, alpha=opacity, label="All Types")
                    plt.boxplot([data for data in allBx[malwareType]], positions=range(len(timePointsMonth)), showfliers=False, vert=True)

        plt.xlabel("Scan Month")
        plt.ylabel("VirusTotal Positives")
        plt.xticks(range(len(timePointsMonth)), timePointsMonth, rotation=90, fontsize=5)
        plt.legend(loc='lower right', fontsize=8)
        plt.tight_layout()
        #plt.show()
        figurePath = "Positives_evolution_median_box_month" if plotTitle == "" else plotTitle
        plt.savefig("./%s.pdf" % figurePath)
        plt.savefig("./%s.pgf" % figurePath)


        # 3. The medians per year
        plt.cla()
        opacity = 0.8
        for malwareType in types:
            color = ACMColors[types.index(malwareType) % len(ACMColors)] if useColors == "ACM" else getRandomHexColor()
            marker, line = markers[types.index(malwareType)], lines[types.index(malwareType)]
            if len(allXs_year[malwareType]) > 0:
                if malwareType == "all":
                    plt.plot(allXs_year[malwareType], allYs_year[malwareType], color="gray", marker=marker, linestyle="-", linewidth=4.0, alpha=opacity, label="All Types")
                else:
                    plt.plot(allXs_year[malwareType], allYs_year[malwareType], color=color, marker=marker, linestyle=line, alpha=opacity, label=malwareType)

        plt.xlabel("Scan Year")
        plt.ylabel("VirusTotal Positives")
        plt.xticks(range(len(timePointsYear)), timePointsYear, rotation=45, fontsize=10)
        plt.legend(loc='lower right', fontsize=8)
        plt.tight_layout()
        #plt.show()
        figurePath = "Positives_evolution_median_year" if plotTitle == "" else plotTitle
        plt.savefig("./%s.pdf" % figurePath)
        plt.savefig("./%s.pgf" % figurePath)


        # 4. The median of "all" + boxes and whiskers
        plt.cla()
        opacity = 0.8
        for malwareType in types:
            color = ACMColors[types.index(malwareType) % len(ACMColors)] if useColors == "ACM" else getRandomHexColor()
            marker, line = markers[types.index(malwareType)], lines[types.index(malwareType)]
            if len(allXs_year[malwareType]) > 0:
                if malwareType == "all":
                    plt.plot(allXs_year[malwareType], allYs_year[malwareType], color="gray", marker=marker, linestyle="-", linewidth=4.0, alpha=opacity, label="All Types")
                    plt.boxplot([data for data in allBx_year[malwareType]], positions=range(len(timePointsYear)), showfliers=False, vert=True)


        plt.xlabel("Scan Year")
        plt.ylabel("VirusTotal Positives")
        plt.xticks(range(len(timePointsYear)), timePointsYear, rotation=90, fontsize=5)
        plt.legend(loc='lower right', fontsize=8)
        plt.tight_layout()
        #plt.show()
        figurePath = "Positives_evolution_median_box_year" if plotTitle == "" else plotTitle
        plt.savefig("./%s.pdf" % figurePath)
        plt.savefig("./%s.pgf" % figurePath)


        # 2. Second the standard deviations figures
        plt.cla()
        opacity = 0.8
        for malwareType in types:
            color = ACMColors[types.index(malwareType) % len(ACMColors)] if useColors == "ACM" else getRandomHexColor()
            marker, line = markers[types.index(malwareType)], lines[types.index(malwareType)]
            if len(allXs[malwareType]) > 0:
                if malwareType == "all":
                    plt.plot(allXs[malwareType], allSt[malwareType], color="gray", marker=marker, linestyle="-", linewidth=4.0, alpha=opacity, label="All Types")
                else:
                    plt.plot(allXs[malwareType], allSt[malwareType], color=color, marker=marker, linestyle=line, alpha=opacity, label=malwareType)

        plt.xlabel("Scan Month")
        plt.ylabel("VirusTotal Positives")
        plt.xticks(range(len(timePointsMonth)), timePointsMonth, rotation=90, fontsize=5)
        plt.yticks([0, 2, 4, 6, 8, 10, 12])
        plt.legend(loc='upper left', fontsize=8)
        plt.tight_layout()
        #plt.show()
        figurePath = "Positives_evolution_stdev_month" if plotTitle == "" else plotTitle
        plt.savefig("./%s.pdf" % figurePath)
        plt.savefig("./%s.pgf" % figurePath)

        # For the yearly scale
        plt.cla()
        opacity = 0.8
        for malwareType in types:
            color = ACMColors[types.index(malwareType) % len(ACMColors)] if useColors == "ACM" else getRandomHexColor()
            marker, line = markers[types.index(malwareType)], lines[types.index(malwareType)]
            if len(allXs[malwareType]) > 0:
                if malwareType == "all":
                    plt.plot(allXs_year[malwareType], allSt_year[malwareType], color="gray", marker=marker, linestyle="-", linewidth=4.0, alpha=opacity, label="All Types")
                else:
                    plt.plot(allXs_year[malwareType], allSt_year[malwareType], color=color, marker=marker, linestyle=line, alpha=opacity, label=malwareType)

        plt.xlabel("Scan Year")
        plt.ylabel("VirusTotal Positives")
        plt.xticks(range(len(timePointsYear)), timePointsYear, rotation=45, fontsize=10)
        plt.yticks([0, 2, 4, 6, 8, 10, 12])
        plt.legend(loc='upper left', fontsize=8)
        plt.tight_layout()
        #plt.show()
        figurePath = "Positives_evolution_stdev_year" if plotTitle == "" else plotTitle
        plt.savefig("./%s.pdf" % figurePath)
        plt.savefig("./%s.pgf" % figurePath)

    except Exception as e:
        prettyPrintError(e)
        return False

    return True

def plotStableMalwareTypes(stableApps, unstableApps, plotTitle="test", useColors="ACM"):
    """
    Plots the stabilized and unstabilized apps in the AMD dataset as a histogram grouped by malware types
    :param stableApps: A structure containing information about apps that have stabilized
    :type stableApps: dict
    :param unstableApps: A structure containing information about apps that have NOT stabilized
    :type unstableApps: dict
    :param plotTitle: The title to give to the plot upon saving to disk
    :type plotTitle: str
    :param useColors: Whether to use ACMColors in the plots (default: ACM)
    :type useColors: str
    :return: A str of the name of the generated histogram figure
    """
    try:
        figurePath = ""
        # Retrieve the counts
        stableCounts, unstableCounts = {}, {}
        for typ in amd_types:
            stableCounts[typ] = 0.0
            unstableCounts[typ] = 0.0

        for app in stableApps:
            typ = stableApps[app][1]
            stableCounts[typ] += 1.0

        for app in unstableApps:
            typ = unstableApps[app][1]
            unstableCounts[typ] += 1.0

        # Build the bar chart
        #fig, ax = plt.subplots()
        index = np.arange(len(amd_types))
        bar_width = 0.35
        opacity = 0.8
        color1 = ACMColors[0] if useColors == "ACM" else getRandomHexColor()
        color2 = ACMColors[2] if useColors == "ACM" else getRandomHexColor()

        for typ in amd_types:
            rects1 = plt.bar(amd_types.index(typ), stableCounts[typ], bar_width, alpha=opacity, color=color1)
            rects2 = plt.bar(amd_types.index(typ)+bar_width, unstableCounts[typ], bar_width, alpha=opacity, color=color2)
            autolabel(rects1, len(stableApps))
            autolabel(rects2, len(unstableApps))
 
        plt.xlabel("Malware types")
        plt.ylabel("Counts of Apps")
        plt.xticks(index + bar_width, tuple(amd_types), rotation=45)
        plt.legend(handles=[Line2D([0], [0], color=color1, lw=4, label='Total stable: %s' % len(stableApps)), Line2D([0], [0], color=color2, lw=4, label='Total unstable: %s' % len(unstableApps))])
        plt.tight_layout()
        #plt.show()
        figurePath = "Bar_stability_%s" % plotTitle
        plt.savefig("./%s.pdf" % figurePath)
        plt.savefig("./%s.pgf" % figurePath)
        plt.clf()

    except Exception as e:
        prettyPrintError(e)
        return ""

    return figurePath

def autolabel(rects, total):
    """
    Attach a text label above each bar displaying its height
    """
    for rect in rects:
        height = rect.get_height()
        plt.text(rect.get_x() + rect.get_width()/2., 1.05*(height/2), '%s%%' % str(round((height/float(total))*100.0, 2)), ha='center', va='bottom', rotation=90)

def summarizeStableVsUnstable(datasetDir, vtReportsDirs, familiesAndTypesMapping={}, stability="positives", plotFigures=False, plotTitle="test", useColors="ACM"):
    """
    Prints (and plots) a summary of differences between apps whose VirusTotal scan reports did (not) stabilize within a dataset
    :param datasetDir: The list of apps in a dataset or the directory containing their APK archives
    :type datasetDir: list or str
    :param vtReportsDirs: The directories containing the VirusTotal reports 
    :type vtReportsDirs: list or str
    :param familiesAndTypesMapping: A structure that maps apps to malware families and types
    :type familiesAndTypesMapping: dict
    :param stability: The metric to adopt upon checking the stability of an app's scan report (default: positives)
    :type stability: str
    :param plotFigures: Whether to plot the differences between stable and unstable apps (default: False)
    :type plotFigures: boolean
    :param plotTitle: The titles to give to plots upon saving them to disk
    :type plotTitle: str
    :param useColors: Whether to use ACMColors or to generate random colors for the plots (default: ACM)
    :type useColors: str
    :return: Three str's depicting paths to the generated figures
    """
    try:
        distFigure, typeFigure, visFigure = "", "", ""
        # First get the stable and unstable apps
        stableApps, unstableApps = getTimeToStabilize(datasetDir, vtReportsDirs, familiesAndTypesMapping, stability)
        # Calculate basic differences
        # Mean/median/std of positives and totals
        meanStable, medianStable, stdStable = mean([stableApps[s][5] for s in stableApps]), median([stableApps[s][5] for s in stableApps]), std([stableApps[s][5] for s in stableApps])
        prettyPrint("Mean, median, std. deviation of positives for stable apps: %s, %s, and %s" % (meanStable, medianStable, stdStable), "output")
        meanStable, medianStable, stdStable = mean([stableApps[s][6] for s in stableApps]), median([stableApps[s][6] for s in stableApps]), std([stableApps[s][6] for s in stableApps])
        prettyPrint("Mean, median, std. deviation of totals for stable apps: %s, %s, and %s" % (meanStable, medianStable, stdStable), "output")
        # Unstables
        meanUnstable, medianUnstable, stdUnstable = mean([unstableApps[s][5] for s in unstableApps]), median([unstableApps[s][5] for s in unstableApps]), std([unstableApps[s][5] for s in unstableApps])
        prettyPrint("Mean, median, std. deviation of positives for unstable apps: %s, %s, and %s" % (meanUnstable, medianUnstable, stdUnstable), "info2")
        meanUnstable, medianUnstable, stdUnstable = mean([unstableApps[s][6] for s in unstableApps]), median([unstableApps[s][6] for s in unstableApps]), std([unstableApps[s][6] for s in unstableApps])
        prettyPrint("Mean, median, std. deviation of totals for unstable apps: %s, %s, and %s" % (meanUnstable, medianUnstable, stdUnstable), "info2")
        # Mean/media/std of ages
        stableAges, unstableAges = [], []
        for s in stableApps:
            first_seen = datetime.strptime(stableApps[s][3], "%Y-%m-%d %H:%M:%S")
            today = datetime.fromtimestamp(time.time())
            age = (today - first_seen).days / 360.0
            stableAges.append(age)
        for u in unstableApps:
            first_seen = datetime.strptime(unstableApps[u][3], "%Y-%m-%d %H:%M:%S")
            today = datetime.fromtimestamp(time.time())
            age = (today - first_seen).days / 360.0
            unstableAges.append(age)
                 
        meanStable, medianStable, stdStable = mean(stableAges), median(stableAges), std(stableAges)
        prettyPrint("Mean, median, std. deviation of age for stable apps: %s, %s, and %s" % (meanStable, medianStable, stdStable), "output")
        meanUnstable, medianUnstable, stdUnstable = mean(unstableAges), median(unstableAges), std(unstableAges)
        prettyPrint("Mean, median, std. deviation of age for unstable apps: %s, %s, and %s" % (meanUnstable, medianUnstable, stdUnstable), "info2")

        # Print families with more than 5%
        stableFamilies, unstableFamilies = {}, {}
        for s in stableApps:
            family = familiesAndTypesMapping[s][0]
            if not family in stableFamilies.keys():
                stableFamilies[family] = 0.0

            stableFamilies[family] += 1.0
            unstableFamilies[family] = 0.0
        for s in unstableApps:
            family = familiesAndTypesMapping[s][0]
            if not family in unstableFamilies.keys():
                unstableFamilies[family] = 0.0

            unstableFamilies[family] += 1.0

        for stable in sortDictByValue(stableFamilies, True):
            family, counts = stable
            if counts/float(len(stableApps)) >= 0.05:
                prettyPrint("Family: %s, contributed %s%% of stable apps" % (family, round(counts/float(len(stableApps))*100.0, 2)), "output")
        for unstable in sortDictByValue(unstableFamilies, True):
            family, counts = unstable
            if counts/float(len(unstableApps)) >= 0.05:
                prettyPrint("Family: %s, contributed %s%% of unstable apps" % (family, round(counts/float(len(unstableApps))*100.0, 2)), "info2")

        # Calculate and plot year distribution
        stableYears, unstableYears = {}, {}
        for app in stableApps:
            first_seen = stableApps[app][3] 
            year = first_seen[:first_seen.find('-')]
            if not year in stableYears.keys():
                stableYears[year] = 0.0
            stableYears[year] += 1.0
            unstableYears[year]= 0.0 
        for app in unstableApps:
            first_seen = unstableApps[app][3] 
            year = first_seen[:first_seen.find('-')]
            if not year in stableYears.keys():
                unstableYears[year] = 0.0
            unstableYears[year] += 1.0

        # Plot figures if instructed to
        if plotFigures:
            # 1. Distribution of un-/stable apps by year
            if VERBOSE == "ON":
                prettyPrint("Plotting distributions of un-/stable grouped by \"first_seen\" year", "debug")

            all_years = stableYears.keys()
            all_years.sort()
            index = np.arange(len(all_years))
            bar_width = 0.35
            opacity = 0.8
            color1 = ACMColors[0] if useColors == "ACM" else getRandomHexColor()
            color2 = ACMColors[2] if useColors == "ACM" else getRandomHexColor()
            for year in all_years:
                rects1 = plt.bar(all_years.index(year), stableYears[year], bar_width, alpha=opacity, color=color1)
                rects2 = plt.bar(all_years.index(year)+bar_width, unstableYears[year], bar_width, alpha=opacity, color=color2)
                autolabel(rects1, len(stableApps))
                autolabel(rects2, len(unstableApps))

            plt.xlabel("\"first_seen\" Years")
            plt.ylabel("Counts of Apps")
            plt.xticks(index + bar_width, tuple(all_years), rotation=45)
            plt.legend(handles=[Line2D([0], [0], color=color1, lw=4, label='Total stable: %s' % len(stableApps)), Line2D([0], [0], color=color2, lw=4, label='Total unstable: %s' % len(unstableApps))])
            plt.tight_layout()
            #plt.show()
            distFigure = "Bar_stability_year_%s" % plotTitle
            plt.savefig("./%s.pdf" % distFigure)
            plt.savefig("./%s.pgf" % distFigure)
            plt.clf()

            # 2. Distribution of un-/stable apps by malware type
            if VERBOSE == "ON":
                prettyPrint("Plotting distributions of un-/stable grouped by malware type", "debug")
            
            typeFigure = plotStableMalwareTypes(stableApps, unstableApps) # Was already implemented before

            # 3. Visualization of static feature vectors
            stableVectors, unstableVectors = [], []
            for s in stableApps:                                                                                                                                                                             
                if os.path.exists("%s/amd/static/%s.static" % (FEATURE_VECTORS, s)):
                    stableVectors.append(eval(open("%s/amd/static/%s.static" % (FEATURE_VECTORS, s)).read()))
            for u in unstableApps:
                if os.path.exists("%s/amd/static/%s.static" % (FEATURE_VECTORS, s)):
                    unstableVectors.append(eval(open("%s/amd/static/%s.static" % (FEATURE_VECTORS, s)).read()))
            # Reduce the dimensionality of the feature vectors and plot them
            #if reduceAndVisualize(stableVectors+unstableVectors, [0]*len(stableVectors)+[1]*len(unstableVectors), dim=2, reductionAlgorithm=2, plottingTool="matplotlib"):
            #    visFigure = "Visualization_2D_%s" % plotTitle



    except Exception as e:
        prettyPrintError(e)
        return "", "", ""

    return distFigure, typeFigure, visFigure

