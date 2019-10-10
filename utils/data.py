#!/usr/bin/python

from Maat.conf.config import *
from Maat.utils.graphics import *
from Maat.utils.misc import *
import os, random, subprocess, pickle, zipfile, shutil
import json, exceptions, time, difflib, requests, gc
import numpy
from androguard.misc import *
import networkx as nx
from skimage.measure import compare_ssim
import imutils
import cv2
from alignment.sequence import Sequence
from alignment.vocabulary import Vocabulary
from alignment.sequencealigner import SimpleScoring, GlobalSequenceAligner

def alignDroidmonTraces(fstTrace, scndTrace):
    """
    Aligns two Droidmon sequences in terms of their API calls a la protein sequence alignment
    :param fstTrace: The first droidmon trace to align
    :type fstTrace: list of str
    :param scndTrace: The second droidmon trace to align
    :type scndTrace: list of str
    :return: A float depicting alignment score (number of alignments / len(min(fstTrace, scndTrace))
    """
    try:
        scores = []
        a, b = Sequence(fstTrace), Sequence(scndTrace)
        v = Vocabulary()
        aEncoded, bEncoded = v.encodeSequence(a), v.encodeSequence(b)
        # Define scoring: +1 for match, -1 for mismatch
        scoring = SimpleScoring(1, -1)
        aligner = GlobalSequenceAligner(scoring, -1) # -1 for alignment gap
        score, encodeds = aligner.align(aEncoded, bEncoded, backtrace=True)
        for encoded in encodeds:
            alignment = v.decodeSequenceAlignment(encoded)
            score = float(alignment.identicalCount)/len(min(fstTrace, scndTrace))
            scores.append(score)

    except Exception as e:
        prettyPrintError(e)
        return 0.0

    score = 0.0 if len(scores) == 0 else sum(scores)/float(len(scores))

    return score

def compareVirusTotalBehavior(behavior1, behavior2):
    """
    Compares two dictionaries depicting the runtime behaviors of two apps as reported by VirusTotal
    :param behavior1: The runtime behavior information of the first app
    :type behavior1: dict
    :param behavior2: The runtime behavior information of the second app
    :type behavior2: dict
    :return: A float depicting the similarity between the behaviors (0.0 = no similarity, 1.0 = exact app)
    """
    try:
        # Find the similar keys
        commonKeys = list(set(behavior1.keys()).intersection(set(behavior2.keys())))
        if len(commonKeys) < 1:
            prettyPrint("Could not find any common keys", "warning")
            return 0.0


        # Iterate over lists and compare them
        similarities = []
        # Add zeros for the uncommon keys in either behaviors
        similarities += [0.0] * (len(behavior1) + len(behavior2) - len(commonKeys))
        for key in commonKeys:
            if not key == "sandbox-version":
                if key == "dynamically_called_methods":
                    # Flatten the lists of methods
                    methods1, methods2 = [], []
                    for method in behavior1["dynamically_called_methods"]:
                        m = method["method"]
                        args = ",".join(method["args"]) if "args" in method.keys() else ""
                        methods1.append("%s(%s)" % (m, args))
                    for method in behavior2["dynamically_called_methods"]:
                        m = method["method"]
                        args = ",".join(method["args"]) if "args" in method.keys() else ""
                        methods2.append("%s(%s)" % (m, args))
                    # Compare the lists
                    similarities.append(listsRatio(methods1, methods2))
                elif key == "contacted_urls":
                    # Flatten the lists of urls
                    urls1 = [url["url"] for url in behavior1["contacted_urls"]]
                    urls2 = [url["url"] for url in behavior2["contacted_urls"]]
                    # Compare the lists
                    similarities.append(listsRatio(urls1, urls2))
                else: 
                    # Add similarity to list of similarities
                    similarities.append(listsRatio(behavior1[key], behavior2[key]))

        # Calculate the final score
        similarity = 0.0 if len(similarities) == 0 else sum(similarities)/float(len(similarities))

    except Exception as e:
        prettyPrintError(e)
        return 0.0


    return similarity

def diffAppCode(app1, app2, fastMode=False):
    """
    Diffs (app1-app2) the source code of two Android apps
    :param app1: The path to the app to which new code is presumed to be added (e.g., repackaged malware)
    :type app1: str
    :param app2: The path to the app used as reference point
    :type app2: str
    :param fastMode: Whether to return once any difference has been found (default: False)
    :type fastMode: boolean
    :return: A dict including different classes and the different code in them
    """
    try:
        # Start diffing
        diff = {}
        # 1.0 If fastMode enabled, try diffing the classes.dex using two techniques
        if fastMode:
            try:
                prettyPrint("Diffing the \"classes.dex\" files using ZipFile")
                # Technique 1: unzip APK and check classes.dex
                if hashlib.sha1(getClassesDEX(app1)).hexdigest() == hashlib.sha1(getClassesDEX(app2)).hexdigest():
                    diff["differences"] = False
                else:
                    diff["differences"] = True
                     
                return diff
            except Exception as e:
                prettyPrint("Could not diff the \"classes.dex\"", "warning")
        
        # Ignored under fastMode    
        prettyPrint("Analyzing apps")
        apk1, dex1, vm1 = AnalyzeAPK(app1)
        apk2, dex2, vm2 = AnalyzeAPK(app2)
        dex1, dex2 = dex1[0], dex2[0]
        if fastMode:
            try:
                # Technique 2: compare classes.dex retrieved from androguard 
                prettyPrint("Take 2: Diffing the \"classes.dex\" files using androguard")
                if hashlib.sha1(apk1.get_file('classes.dex')).hexdigest() == hashlib.sha1(apk2.get_file('classes.dex')).hexdigest():
                    diff["differences"] = False
                else:
                    diff["differences"] = True
              
                return diff
            except Exception as e:
                prettyPrint("Could not diff the \"classes.dex\" again. Trying decompiled code", "warning")

        # Add the packaged names 
        diff["piggybacked"], diff["original"], diff["differences"] = apk1.get_package(), apk2.get_package(), {}
        # 1.1. Retrieve newly-added classes
        new_classes = list(set(dex1.get_classes_names()).difference(dex2.get_classes_names()))
        if len(new_classes) > 0:
            # Return if fastMode enabled
            if fastMode:
                diff["differences"] = True
                prettyPrint("Apps \"%s\" and \"%s\" are different. Returning \"True\"" % (app1, app2), "debug")
                return diff

            # 1.2. Add code to diff dictionary
            prettyPrint("Adding %s newly-added classes to difference" % len(new_classes)) 
            for new_class in new_classes:
                c = dex1.get_class(new_class)
                diff["differences"][new_class] = c.get_source()

        # Diff existing classes
        old_classes = list(set(dex1.get_classes_names()).intersection(set(dex2.get_classes_names())))
        prettyPrint("Checking %s common classes" % len(old_classes))
        for old_class in old_classes:
            different = False
            source1, source2 = dex1.get_class(old_class).get_source(), dex2.get_class(old_class).get_source()
            # Get raw code
            raw1, raw2 = "N/A", "N/A"
            try:
                raw1 = dex1.get_class(old_class).get_raw()    
            except KeyError as ke:
                #prettyPrint("Could not retrieve raw code of class \"%s\" from \"%s\"" % (old_class, app1), "warning")
                pass
            try:
                raw2 = dex2.get_class(old_class).get_raw()    
            except KeyError as ke:
                #prettyPrint("Could not retrieve raw code of class \"%s\" from \"%s\"" % (old_class, app2), "warning")
                pass

            # Compare hashes of source code first
            if hashlib.sha1(source1).hexdigest() != hashlib.sha1(source2).hexdigest():
                differet = True
                # Compare the raw code if available
                if raw1 != "N/A" and raw2 != "N/A":
                    if hashlib.sha1(raw1).hexdigest() == hashlib.sha1(raw2).hexdigest():
                        # Glitch in decompilation?
                        different = False

                # Last line of defense in case of inconsistency
                if min(len(source1), len(source2)) / max(len(source1), len(source2)) >= 0.95 and stringRatio(source1, source2) >= 0.95:
                    # False alarm? Carry on
                    #prettyPrint("Yo, weird case here!! \"[CLASS]: %s,\n\t>> len(source1)=%s, len(source2)=%s,\n\t>> stringRatio(source1, source2)=%s,\n\t>> SHA1(source1)=%s,\n\t  SHA1(source2)=%s" % (old_class, len(source1), len(source2), stringRatio(source1, source2), hashlib.sha1(source1).hexdigest(), hashlib.sha1(source2).hexdigest()), "warning")
                    #print diffStrings(source1, source2)
                    different = False
                    
                # Return if fastMode enabled
                if different:
                    if fastMode:
                        diff["differences"] = True
                        prettyPrint("Apps \"%s\" and \"%s\" are different. Returning \"True\"" % (app1, app2), "debug")
                        return diff
                
                    # Add different code to dictionary
                    prettyPrint("Class \"%s\" is different. Retrieving differences" % old_class, "debug")
                    new_code = str(set(source1.split("\n")).difference(set(source2.split("\n"))))
                    diff["differences"][old_class] = new_code
    

    except Exception as e:
        prettyPrintError(e)
        return {}

    return diff


def diffStrings(expected, actual):
    """
    Helper function. Returns a string containing the unified diff of two multiline strings.
    
    """
    expected=expected.splitlines(1)
    actual=actual.splitlines(1)

    diff=difflib.unified_diff(expected, actual)

    return ''.join(diff)

def diffTraces(traceX, traceY, ignoreArguments=True):
    """
    Diffs two traces and returns the number of differences
    :param traceX: The first trace
    :type traceX: list of str
    :param traceY: The second trace
    :type traceY: list of str
    :param ignoreArguments: Whether to consider the method arguments in the comparisons
    :type ignoreArguments: bool
    :return: An int depicting the number of differences between the two traces
    """
    try:
        diffs = abs(len(traceX)-len(traceY))
        upperbound = len(traceX) if len(traceX) <= len(traceY) else len(traceY)
        for index in range(upperbound):
             callX = traceX[index] if not ignoreArguments else traceX[index][:traceX[index].find("(")]
             callY = traceY[index] if not ignoreArguments else traceY[index][:traceY[index].find("(")]
             if callX != callY:
                 diffs += 1

    except Exception as e:
        prettyPrintError(e)
        return -1

    return diffs


def extractAPKInfo(targetAPK, infoLevel=1, saveInfo=True):
    """
    Statically analyzes APK and extracts information from it
    :param targetAPK: The path to the APK to analyze
    :type targetAPK: str
    :param infoLevel: The depth of information to retrieve (e.g., names, components, classes, etc.)
    :type infoLevel: int
    :param saveInfo: Whether to save the extracted information to file
    :type saveInfo: boolean
    :return: A tuple of the three objects retrurned by androguard and a dict containing necessary information
    """
    try:
        apkData = {}
        prettyPrint("Analyzing target APK \"%s\"" % targetAPK)
        apk, dex, vm = AnalyzeAPK(targetAPK)
        dex = dex[0] if type(dex) == list else dex
        apkData["name"] = apk.get_app_name()
        apkData["package"] = apk.get_package()
        apkData["icon"] = apk.get_app_icon()
        #apkData["signature"] = apk.get_signature()
        #apkData["certificate"] = apk.get_certificate(apk.get_signature_name())
        apkData["issuer"] = apk.get_certificate(apk.get_signature_name()).issuer.human_friendly
        with zipfile.ZipFile(targetAPK, "r") as zip_ref:
            try:
                destination = "%s/tmp_%s/" % (targetAPK[:targetAPK.rfind('/')], apkData["package"])
                zip_ref.extractall(destination)
                zip_ref.close()
            except zipfile.BadZipfile as e:
                prettyPrint("Could not retrieve the app's icon", "warning") 

        if infoLevel >= 2:
            apkData["activities"] = apk.get_activities()
            apkData["permissions"] = apk.get_permissions()
            apkData["providers"] = apk.get_providers()
            apkData["receivers"] = apk.get_receivers()
            apkData["services"] = apk.get_services()
            apkData["files"] = apk.get_files()
            
        if infoLevel >= 3:
            apkData["libraries"] = [l for l in apk.get_libraries()]
            apkData["classes"] = dex.get_classes_names()
            apkData["methods"] = []
            for c in apkData["classes"]:
                for m in dex.get_methods_class(c):
                    apkData["methods"].append("%s->%s" % (c, m.name))
        if infoLevel >= 4:
            try:
                callgraph = vm.get_call_graph()
                apkData["callgraph"] = "%s/call_graph.gpickle" % destination
            except Exception as e:
                apkData["callgraph"] = None

        if saveInfo:
            prettyPrint("Saving extracted info to \"%s\"" % destination, "debug") 
            if not os.path.exists(destination):
                prettyPrint("Could not find the temporary directory \"%s\". Saving aborted"  % destination, "warning")
                return apk, dex, vm, apkData
            else:
                open("%s/data.txt" % destination, "w").write(str(apkData))
                if infoLevel >= 4:
                    if apkData["callgraph"] != None:
                        nx.write_gpickle(callgraph, "%s/call_graph.gpickle" % destination)

    except exceptions.RuntimeError as re:
        prettyPrintError(re)
        
    except Exception as e:
        prettyPrintError(e)
        return None, None, None, {}

    return apk, dex, vm, apkData

def hex_to_rgb(value):
    value = value.lstrip('#')
    lv = len(value)
    return tuple(int(value[i:i+lv/3], 16) for i in range(0, lv, lv/3))

def getPackageNameFromAPK(apkPath):
    """
    Retrieves the package name from an APK using AAPT
    :param apkPath: The path to the APK archive to process
    :type apkPath: str
    :return: A string depicting the retrieved packaged name
    """
    try:
        pkg_cmd = ["aapt", "dump", "badging", apkPath]
        pkg_cmd_output = subprocess.Popen(pkg_cmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]                                                                       
        magic = "package: name='"
        index = pkg_cmd_output.find(magic)+len(magic)                                           
        app_pkg = pkg_cmd_output[index:pkg_cmd_output.find("'", index)].replace(" ", "")
    except Exception as e:
        prettyPrintError(e)
        return ""

    return app_pkg

def getVTLabel(VTReportKey, labeling="vt1-vt1"):
    """
    Figures out the label of an app according to its VirusTotal and the passed label
    :param VTReportKey: The key used to look for the report (i.e., the SHA256 hash of the app)
    :type VTReportKey: str
    :param labeling: 
    :type labeling:
    :return: an int depicting the class of the app according to the adopted labeling scheme (1 for malicious, 0 for benign, -1 for unknown)
    """
    try:
        # Retrieve the APK's label according to a labeling scheme
        targetLabel = -1    
        if os.path.exists("%s/%s.report" % (VT_REPORTS_DIR, VTReportKey)):
            report = eval(open("%s/%s.report" % (VT_REPORTS_DIR, VTReportKey)).read())
            #prettyPrint("VirusTotal report \"%s.report\" found" % targetKey, "debug")
            if "positives" in report.keys():
                if labeling == "old":
                    if "additional_info" in report.keys():
                        if "positives_delta" in report["additional_info"].keys():
                            targetLabel = 1 if report["positives"] - report["additional_info"]["positives_delta"] >= 1 else 0

                elif labeling == "vt1-vt1":
                    targetLabel = 1 if report["positives"] >= 1 else 0
                elif labeling == "vt50p-vt50p":
                    targetLabel = 1 if report["positives"]/float(report["total"]) >= 0.5 else 0
                elif labeling == "vt50p-vt1":
                    if report["positives"]/float(report["total"]) >= 0.5:
                        targetLabel = 1
                    elif report["positives"] == 0:
                        targetLabel = 0
                    else:
                        targetLabel = -1

    except Exception as e:
        prettyPrintError(e)
        return -1

    return targetLabel


def getVTReport(VTAPIKey, VTHash, allinfo="true"):
    """
    Download the report corresponding to a hash from VirusTotal
    :param VTAPIKey: The VirusTotal API key needed to download the report
    :type VTAPIKey: str
    :param VTHash: The SHA1 or SHA256 hash of the resource
    :type VTHash: str
    :param allinfo: Whether to download the full or short report from VirusTotal (true [Default]/false)
    :type allinfo: str
    :return: A dict containing the report downloaded from VirusTotal
    """
    try:
        URL = "https://www.virustotal.com/vtapi/v2/file/report?apikey=%s&resource=%s&allinfo=%s" % (VTAPIKey, VTHash, allinfo)
        response = requests.get(URL).text
        if len(response) > 0:
            return json.loads(response)

    except Exception as e:
        print "[*] Error encountered: %s" % e
        return {}


def injectBehaviorInTrace(targetTrace, insertionProbability, multipleBehaviors=False):
    """
    Injects malicious blocks of pre-defined malicious behaviors into a target trace with a the likelihood of [insertionProbability]
    :param targetTrace: The trace to inject the behaviors in
    :type targetTrace: list
    :param insertionProbability: The probability with which behaviors are injected into the target trace
    :type insertionProbability: float
    :param multipleBehaviors: Whether to inject different behaviors in the same target trace
    :type multipleBehaviors: bool
    :return: A list depicting the new trace with the inserted behavior(s)
    """
    try:
        newTrace = []
        # Retrieve store behaviors
        behaviors = loadMaliciousBehaviors()
        # Iterate over the target trace and inject the malicious behaviors
        constantBehavior = behaviors[random.randint(0, len(behaviors)-1)] if not multipleBehaviors else ""
        currentIndex = 0
        # Find insertion points and behaviors
        positions = []
        while currentIndex < len(targetTrace):
            if flip(insertionProbability) == "YES":
                b = constantBehavior if constantBehavior != "" else behaviors[random.randint(0, len(behaviors)-1)]
                # Insert behavior
                positions.append((currentIndex+1, b))
                # Update current index
                currentIndex = currentIndex + len(b) + 1
        # Insert behaviors in positions
        print positions
        newTrace = [] + targetTrace
        if len(positions) > 0:
            for p in positions:
                before = newTrace[:p[0]]
                after = newTrace[p[0]:]
                middle = ["%s()" % i for i in p[1]]
                before.extend(middle)
                newTrace = before+after
                
    except Exception as e:
        prettyPrintError(e)
        return []

    return newTrace

def loadNumericalFeatures(featuresFile, delimiter=","):
    """
    Loads numerical features from a file and returns a list

    :param featuresFile: The file containing the feature vector
    :type featuresFile: str
    :param delimiter: The character separating numerical features
    :type delimiter: str    
    """
    try:
        if not os.path.exists(featuresFile):
            prettyPrint("Unable to find the features file \"%s\"" % featuresFile, "warning")
            return []
        content = open(featuresFile).read()
        if content.lower().find("[") != -1 and content.lower().find("]") != -1:
            features = eval(content)
        else:
            features = [float(f) for f in content.replace(' ','').split(delimiter)]

    except Exception as e:
        prettyPrintError(e)
        return []

    return features

def loadMaliciousBehaviors():
    """
    Loads malicious behaviors from the database
    return: A list of malicious behaviors stored in the database
    """
    try:
        MaatDB = DB()
        cursor = MaatDB.select([], "behaviors")
        behaviors = cursor.fetchall()
        if len(behaviors) < 1:
            prettyPrint("Could not retrieve malicious behaviors from the database. Inserting behaviors in \"%s\"" % MALICIOUS_BEHAVIORS, "warning")
        content = open(MALICIOUS_BEHAVIORS).read().split('\n')
        if len(content) < 1:
             prettyPrint("Could not retrieve any behaviors from \"%s\"" % MALCIOUS_BEHAVIORS, "error")
             return []
        for line in content:
            if len(line) > 1:
                desc = line.split(':')[0]
                sequence = line.split(':')[1].replace(' ','')
                timestamp = getTimeStamp(includeDate=True)
                MaatDB.insert("behaviors", ["bDesc", "bSequence", "bTimestamp"], [desc, sequence, timestamp])
        # Lazy guarantee of same data format
        cursor = MaatDB.select([], "behaviors")
        behaviors = cursor.fetchall()

    except Exception as e:
        prettyPrintError(e)
        return []

    return behaviors

def logEvent(msg):
    try:
        open(LOG_FILE, "w+").write(msg)

    except Exception as e:
        prettyPrintError(e)
        return False

    return True 

def matchAPKs(sourceAPK, targetAPKs, matchingDepth=1, matchingThreshold=0.67, matchWith=10, useSimiDroid=False, fastSearch=True, matchingTimeout=500, labeling="vt1-vt1", useLookup=False):
    """
    Compares and attempts to match two APK's and returns a similarity measure
    :param sourceAPK: The path to the source APK (the original app you wish to match)
    :type sourceAPK: str
    :param targetAPK: The path to the directory containing target APKs (against which you wish to match)
    :type targetAPK: str
    :param matchingDepth: The depth and rigorosity of the matching (between 1 and 4)
    :type matchingDepth: int
    :param matchingThreshold: A similarity percentage above which apps are considered similar
    :type matchingThreshold: float
    :param matchWith: The number of matchings to return (default: 1)
    :type matchWith: int
    :param useSimiDroid: Whether to use SimiDroid to perform the comparison
    :type useSimiDroid: boolean
    :param fastSearch: Whether to return matchings one maximum number of matches [matchWith] is reached
    :type fastSearch: boolean
    :param matchingTimeout: The time (in seconds) to allow the matching process to continue
    :type matchingTimeoue: int
    :param labeling: The labeling scheme adopted to label APK's as malicious and benign
    :type labeling: str
    :param useLookup: Whether to skip analyzing every app and depend on lookup structs to hasten the experiments
    :type useLookup: boolean
    :return: A list of tuples (str, (float, float) depicting the matched app, the similarity measure and the matched app's label
    """
    try:
        similarity = 0.0
        # Get the target apps
        targetApps = glob.glob("%s/*" % targetAPKs) if useSimiDroid == False else glob.glob("%s/*.apk" % targetAPKs)
        # Randomize?
        random.shuffle(targetApps)        
        if len(targetApps) < 1:
            prettyPrint("Could not retrieve any APK's or directories from \"%s\"" % targetApps, "error")
            return []
 
        prettyPrint("Successfully retrieved %s apps from \"%s\"" % (len(targetApps), targetAPKs))
        # Retrieve information from the source APK
        if not useSimiDroid:
            sourceKey = sourceAPK[sourceAPK.rfind("/")+1:].replace(".apk", "")
            if useLookup:
                infoDir = targetApps[0][:targetApps[0].rfind("/")]
                if os.path.exists("%s/%s_data" % (infoDir, sourceKey)):
                    sourceInfo = eval(open("%s/%s_data/data.txt" % (infoDir, sourceKey)).read())
                else:
                    prettyPrint("No lookup info found. Extracting app info", "warning")
                    sourceInfo = extractAPKInfo(sourceAPK, matchingDepth)[-1]
            else:          
                sourceInfo = extractAPKInfo(sourceAPK, matchingDepth)[-1]

            if len(sourceInfo) < 1:
                prettyPrint("Could not extract any info from \"%s\"" % sourceAPK, "error")
                return []

        matchings = {}
        counter = 0
        startTime = time.time()
        for targetAPK in targetApps:
            counter += 1
            # Timeout?
            if counter >= matchingTimeout:
                prettyPrint("Matching timeout", "error")
                return sortDictByValue(matchings, True)
            prettyPrint("Matching with \"%s\", #%s out of %s" % (targetAPK, counter, matchingTimeout), "debug")
            if useSimiDroid == False:
                # Use homemade recipe to perform the comparison
                if not os.path.exists("%s/data.txt" % targetAPK):
                    prettyPrint("Could not find a \"data.txt\" file for app \"%s\". Skipping" % targetAPK, "warning")
                    continue

                # Load pre-extracted target app information
                try:
                    targetInfo = eval(open("%s/data.txt" % targetAPK).read())
                except Exception as e:
                    prettyPrint("Could not load target info. Skipping", "warning")
                    continue
                    
                # Retrieve the APK's label according to a labeling scheme
                targetLabel = -1
                targetKey = targetAPK[targetAPK.rfind("/")+1:].replace("_data", "")
                if os.path.exists("%s/%s.report" % (VT_REPORTS_DIR, targetKey)):
                    report = eval(open("%s/%s.report" % (VT_REPORTS_DIR, targetKey)).read())
                    prettyPrint("VirusTotal report \"%s.report\" found" % targetKey, "debug")
                    if "positives" in report.keys():
                        if labeling == "old":
                            if "additional_info" in report.keys():
                                if "positives_delta" in report["additional_info"].keys():
                                    targetLabel = 1 if report["positives"] - report["additional_info"]["positives_delta"] >= 1 else 0
                            else:
                                continue
                        if labeling == "vt1-vt1":
                            targetLabel = 1 if report["positives"] >= 1 else 0
                        elif labeling == "vt50p-vt50p":
                            targetLabel = 1 if report["positives"]/float(report["total"]) >= 0.5 else 0
                        elif labeling == "vt50p-vt1":
                            if report["positives"]/float(report["total"]) >= 0.5:
                                targetLabel = 1
                            elif report["positives"] == 0:
                                targetLabel = 0
                            else:
                                targetLabel = random.randint(0, 1)
  
                # Start the comparison
                similarities = []
                if matchingDepth >= 1:
                    if "name" in sourceInfo.keys() and "name" in targetInfo.keys():
                        similarities.append(stringRatio(sourceInfo["name"], targetInfo["name"]))
                    if "package" in sourceInfo.keys() and "package" in targetInfo.keys():
                        similarities.append(stringRatio(sourceInfo["package"], targetInfo["package"]))
                    if "icon" in sourceInfo.keys() and "icon" in targetInfo.keys():
                        if sourceInfo["icon"] != None and targetInfo["icon"] != None:
                            sourceIcon = "%s/tmp_%s/%s" % (sourceAPK[:sourceAPK.rfind("/")], sourceInfo["package"], sourceInfo["icon"])
                            targetIcon = "%s/%s" % (targetAPK, targetInfo["icon"][targetInfo["icon"].rfind('/')+1:])
                            if os.path.exists(sourceIcon) and os.path.exists(targetIcon):
                                similarities.append(simImages(sourceIcon, targetIcon))
     
                if matchingDepth >= 2:
                    if "activities" in sourceInfo.keys() and "activities" in targetInfo.keys():
                        similarities.append(listsRatio(sourceInfo["activities"], targetInfo["activities"]))
                    if "permissions" in sourceInfo.keys() and "permissions" in targetInfo.keys():
                        similarities.append(listsRatio(sourceInfo["permissions"], targetInfo["permissions"]))
                    if "providers" in sourceInfo.keys() and "providers" in targetInfo.keys():
                        similarities.append(listsRatio(sourceInfo["providers"], targetInfo["providers"]))
                    if "receivers" in sourceInfo.keys() and "receivers" in targetInfo.keys():
                        similarities.append(listsRatio(sourceInfo["receivers"], targetInfo["receivers"]))
                    if "services" in sourceInfo.keys() and "services" in targetInfo.keys():
                        similarities.append(listsRatio(sourceInfo["services"], targetInfo["services"]))
                    if "files" in sourceInfo.keys() and "files" in targetInfo.keys():
                        similarities.append(listsRatio(sourceInfo["files"], targetInfo["files"]))

                if matchingDepth >= 3:
                    if "libraries" in sourceInfo.keys() and "libraries" in targetInfo.keys():
                        similarities.append(listsRatio(sourceInfo["libraries"], targetInfo["libraries"]))
                    if "classes" in sourceInfo.keys() and "classes" in targetInfo.keys():
                        similarities.append(listsRatio(sourceInfo["classes"], targetInfo["classes"]))
                    if "methods" in sourceInfo.keys() and "methods" in targetInfo.keys():
                        similarities.append(listsRatio(sourceInfo["methods"], targetInfo["methods"]))

                if matchingDepth >= 4:
                       if os.path.exists("%s/%s_data/call_graph.gpickle" % (infoDir, sourceKey)) and os.path.exists("%s/call_graph.gpickle" % targetAPK):
                           try:
                               prettyPrint("Loading source graph from \"%s/%s_data/call_graph.gpickle\"" % (infoDir, sourceKey), "debug")
                               sourceGraph = nx.read_gpickle("%s/%s_data/call_graph.gpickle" % (infoDir, sourceKey))
                               prettyPrint("Loading target graph from \"%s/call_graph.gpickle\"" % targetAPK, "debug")
                               targetGraph = nx.read_gpickle("%s/call_graph.gpickle" % targetAPK)
                           except exceptions.EOFError as e:
                                   prettyPrint("Could not read call source or target graphs. Skipping", "warning")
                                   continue
                           if fastSearch:
                               isomorphic = nx.algorithms.could_be_isomorphic(sourceGraph, targetGraph)
                           else:
                               isomorphic = nx.algorithms.is_isomorphic(sourceGraph, targetGraph)
                           if isomorphic:
                               similarities.append(1.0)
                           else:
                               similarities.append(0.0)
            else:
                # Use SimiDroid to perform comparison
                curDir = os.path.abspath(".")
                os.chdir(SIMIDROID_DIR)
                cmd = "java -jar SimiDroid.jar %s %s" % (sourceAPK, targetAPK)
                outFile = "%s-%s.json" % (sourceAPK[sourceAPK.rfind('/')+1:].replace(".apk", ""), targetAPK[targetAPK.rfind("/")+1:].replace(".apk", ""))
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
                p.communicate()
                if not os.path.exists(outFile):
                    prettyPrint("Could not find SimiDroid output file. Skipping", "warning")
                    continue
 
                outContent = json.loads(open(outFile).read())
                os.chdir(curDir)

            if len(similarities) >= 1:
                similarity = float(sum(similarities))/float(len(similarities)) if useSimiDroid == False else float(outContent["conclusion"]["simiScore"])
            else:
                similarity = 0.0
            prettyPrint("Similarity score: %s" % similarity)
            # Delete targetInfo to free memory?
            prettyPrint("Releasing object and invoking Garbage Collector", "debug")
            targetGraph = None
            gc.collect()

            if similarity >= matchingThreshold:
                prettyPrint("Got a match between source \"%s\" and app \"%s\", with score %s" % (sourceAPK[sourceAPK.rfind("/")+1:].replace(".apk", ""), targetAPK[targetAPK.rfind("/")+1:].replace(".apk", ""), similarity), "output")

                if useSimiDroid == False:
                    matchings[targetInfo["package"]] = (similarity, targetLabel)
                else:
                    matchings[targetAPK] = (similarity, targetLabel)

                currentTime = time.time()
                if (fastSearch and len(matchings) >= matchWith) or (currentTime - startTime >= matchingTimeout):
                    # Return what we've got so far
                    if len(matchings) >= matchWith:
                        return sortDictByValue(matchings, True)

    except Exception as e:
        prettyPrintError(e)
        return []

    return sortDictByValue(matchings, True)

def matchAppsDynamic(sourceAPK, dataSource="droidmon", fastSearch=True, includeArguments=True, matchingThreshold=0.67, matchWith=10, labeling="vt1-vt1"):
    """
    Matches apps according to similarities between their traces or runtime behaviors
    :param sourceAPK: The path to the source APK (the original app you wish to match)
    :type sourceAPK: str
    :param infoDir: The path to the directory containing target traces (against which you wish to match)
    :type infoDir: str
    :param dataSource: The source of runtime behavior to compare (options: "droidmon", "virustotal")
    :type dataSource: str
    :param fastSearch: Whether to return matchings one maximum number of matches [matchWith] is reached
    :type fastSearch: boolean
    :param includeArguments: Whether to include method arguments in droidmon traces
    :type includeArguments: boolean
    :param matchingThreshold: A similarity percentage above which apps are considered similar
    :type matchingThreshold: float
    :param matchWith: The number of matchings to return (default: 1)
    :type matchWith: int
    :param fastSearch: Whether to return matchings one maximum number of matches [matchWith] is reached
    :type fastSearch: boolean
    :param labeling: The labeling scheme adopted to label APK's as malicious and benign
    :type labeling: str
    :return: A list of tuples (str, (float, float)) depicting the matched app, the similarity measure and the matched app's label
    """
    try:
        # Get the log/behavior of the source APK
        sourceKey = sourceAPK[sourceAPK.rfind("/")+1:].replace(".apk", "")
        if dataSource == "droidmon":
            sourceLogs = glob.glob("%s/%s*.filtered" % (LOGS_DIR, sourceKey))
            if len(sourceLogs) < 1:
                prettyPrint("Could not find \"Droidmon\" logs for app \"%s\"" % sourceKey, "warning")
                return [] 
                
            sourceLog = sourceLogs[random.randint(0, len(sourceLogs)-1)]
            for log in sourceLogs:
                if os.path.getsize(log) > os.path.getsize(sourceLog):
                     sourceLog = log
            
            sourceBehavior = parseDroidmonLog(sourceLog, includeArguments=includeArguments)

        else:
             if not os.path.exists("%s/%s.report" % (VT_REPORTS_DIR, sourceKey)):
                 prettyPrint("Could not find a \"VirusTotal\" report for \"%s\"" % sourceKey, "warning")
                 return []
                 
             report = eval(open("%s/%s.report" % (VT_REPORTS_DIR, sourceKey)).read())
             if not "additional_info" in report.keys():
                 prettyPrint("Could not find the key \"additional_info\" in the report", "warning")
                 return []

             if not "android-behaviour" in report["additional_info"].keys():
                  prettyPrint("Could not find the key \"android-behaviour\" in the report", "warning")
                  return []

             sourceBehavior = report["additional_info"]["android-behaviour"]

        # Get the target apps
        if dataSource == "droidmon":
            targetApps = glob.glob("%s/*.filtered" % LOGS_DIR)
        elif dataSource == "virustotal":
            targetApps = glob.glob("%s/*.report" % VT_REPORTS_DIR)
        
        if len(targetApps) < 1:
            prettyPrint("Could not find \"Droidmon\" logs or \"VirusTotal\" reports to match apps", "warning")
            return []
            
        matchings = []
        similarity = 0.0
        for target in targetApps:
            # Load targetBehavior
            if dataSource == "droidmon":
                targetBehavior = parseDroidmonLog(target, includeArguments=includeArguments)
            else:
                report = eval(open(target).read())
                try:
                    targetBehavior = report["additional_info"]["android-behaviour"]
                except Exception as e:
                    #prettyPrint("Could not load \"VirusTotal\" runtime behavior for \"%s\". Skipping." % target, "warning")
                    continue
            
            # Retrieve the APK's label according to a labeling scheme
            targetLabel = -1
            tmp = target[target.rfind("/")+1:].replace(".filtered", "")
            targetKey = tmp[:tmp.find("_")] if dataSource == "droidmon" else tmp.replace(".report", "")
            if os.path.exists("%s/%s.report" % (VT_REPORTS_DIR, targetKey)):
                report = eval(open("%s/%s.report" % (VT_REPORTS_DIR, targetKey)).read())
                #prettyPrint("VirusTotal report \"%s.report\" found" % targetKey, "debug")
                if "positives" in report.keys():
                    if labeling == "old":
                        if "additional_info" in report.keys():
                            if "positives_delta" in report["additional_info"].keys():
                                targetLabel = 1 if report["positives"] - report["additional_info"]["positives_delta"] >= 1 else 0
                        else:
                            continue
                    if labeling == "vt1-vt1":
                        targetLabel = 1 if report["positives"] >= 1 else 0
                    elif labeling == "vt50p-vt50p":
                        targetLabel = 1 if report["positives"]/float(report["total"]) >= 0.5 else 0
                    elif labeling == "vt50p-vt1":
                        if report["positives"]/float(report["total"]) >= 0.5:
                            targetLabel = 1
                        elif report["positives"] == 0:
                            targetLabel = 0
                        else:
                            targetLabel = -1

                if targetLabel == -1:
                    prettyPrint("Could not label \"%s\" under the \"%s\" scheme" % (targetKey, labeling), "warning")
                    continue
                # Start the comparison
                if dataSource == "droidmon":
                    # Compare trace
                    similarity = tracesRatio(sourceBehavior, targetBehavior) 
                else:
                    # Compare different lists in the "android-behaviour"
                    similarity = compareVirusTotalBehavior(sourceBehavior, targetBehavior)
                    
                #prettyPrint("Similarity score: %s" % similarity, "debug")

                if similarity >= matchingThreshold:
                    prettyPrint("Got a match between source \"%s\" and app \"%s\", with score %s" % (sourceKey, targetKey, similarity), "output")
                    matchings.append((targetKey, (similarity, targetLabel)))

                if (fastSearch and len(matchings) >= matchWith):
                    # Return what we've got so far
                    if len(matchings) >= matchWith:
                        return matchings[:matchWith]
                    else:
                        return matchings

    except Exception as e:
        prettyPrintError(e)
        return []

    return matchings

def matchTrace(sourceApp, alignTraces=False, compareTraces=False, includeArguments=False, matchingThreshold=0.50, maxChunkSize=0, labeling="vt1-vt1"):
    """
    Matches a droidmon trace to other droidmon traces in Maat's repository organized as clusters according to their lengths
    :param sourceApp: The path to the APK whose trace we wish to match
    :type sourceApp: str
    :param alignTraces: Whether to measure trace similarity according to alignment
    :type alignTraces: boolean
    :param compareTraces: Whether to compare traces or settle for labels of traces in a cluster
    :type compareTraces: boolean
    :param includeArguments: Whether to include method arguments in droidmon traces
    :type includeArguments: boolean
    :param matchingThreshold: A similarity percentage above which apps are considered similar
    :type matchingThreshold: float
    :maxChunkSize: The maximum size of chunks to shorten in traces (default: 0)
    :type maxChunkSize: int
    :param labeling: The labeling scheme adopted to label APK's as malicious and benign
    :type labeling: str
    :return: A list of tuples (str, (float, float)) depicting the matched app, the similarity measure and the matched app's label
    """
    try:
       matchings = []
       sourceKey = sourceApp[sourceApp.rfind("/")+1:].replace(".apk", "")
       if not os.path.exists("%s/%s.report" % (VT_REPORTS_DIR, sourceKey)):
           prettyPrint("Could not find \"VirusTotal\" report for app \"%s\"" % sourceApp, "warning")
           return []
       elif len(glob.glob("%s/Test/%s*.filtered" % (LOGS_DIR, sourceKey))) < 1:
           prettyPrint("Could not find any \"droidmon\" logs for app \"%s\"" % sourceApp, "warning")
           return []

       # Retrieve source logs
       sourceLogs = [parseDroidmonLog(log, includeArguments=includeArguments) for log in glob.glob("%s/Test/%s*.filtered" % (LOGS_DIR, sourceKey))]
       sourceTrace = max(sourceLogs)
       sourceLabel = getVTLabel(sourceKey, labeling)
       # Retrieve the corresponding cluster of logs
       if len(sourceTrace) < 10:
           clusterFile = "%s/Maat_traces_length_10.txt" % LOOKUP_STRUCTS
       elif len(sourceTrace) >= 10 and len(sourceTrace) < 25:
           clusterFile = "%s/Maat_traces_length_1025.txt" % LOOKUP_STRUCTS
       elif len(sourceTrace) >= 25 and len(sourceTrace) < 50:
           clusterFile = "%s/Maat_traces_length_2550.txt" % LOOKUP_STRUCTS
       elif len(sourceTrace) >= 50 and len(sourceTrace) < 75:
           clusterFile = "%s/Maat_traces_length_5075.txt" % LOOKUP_STRUCTS
       elif len(sourceTrace) >= 75 and len(sourceTrace) < 100:
           clusterFile = "%s/Maat_traces_length_75100.txt" % LOOKUP_STRUCTS
       elif len(sourceTrace) >= 100 and len(sourceTrace) < 125:
           clusterFile = "%s/Maat_traces_length_100125.txt" % LOOKUP_STRUCTS
       elif len(sourceTrace) >= 125 and len(sourceTrace) < 150:
           clusterFile = "%s/Maat_traces_length_125150.txt" % LOOKUP_STRUCTS
       elif len(sourceTrace) >= 150 and len(sourceTrace) < 175:
           clusterFile = "%s/Maat_traces_length_150175.txt" % LOOKUP_STRUCTS
       elif len(sourceTrace) >= 175 and len(sourceTrace) < 200:
           clusterFile = "%s/Maat_traces_length_175200.txt" % LOOKUP_STRUCTS
       elif len(sourceTrace) >= 200 and len(sourceTrace) < 300:
           clusterFile = "%s/Maat_traces_length_200300.txt" % LOOKUP_STRUCTS
       elif len(sourceTrace) >= 300 and len(sourceTrace) < 400:
           clusterFile = "%s/Maat_traces_length_300400.txt" % LOOKUP_STRUCTS
       elif len(sourceTrace) >= 400 and len(sourceTrace) < 500:
           clusterFile = "%s/Maat_traces_length_400500.txt" % LOOKUP_STRUCTS
       elif len(sourceTrace) >= 500:
           clusterFile = "%s/Maat_traces_length_500.txt" % LOOKUP_STRUCTS
       
       # Load the traces in the designated cluster
       prettyPrint("Loading cluster file \"%s\"" % clusterFile)
       targetLogs = eval(open(clusterFile).read())
       if compareTraces == False:
           prettyPrint("Basing matching on labels", "debug")
           # Just retrieve the labels of the logs in the cluster
           for log in targetLogs:
               tmp = log[log.rfind("/")+1:].replace(".filtered", "")
               targetKey = tmp[:tmp.find("_")]
               targetLabel = getVTLabel(targetKey, labeling)
               if targetLabel != -1:
                   matchings.append((targetKey, (0.0, targetLabel)))
       else:
           prettyPrint("Matching \"%s\" with %s traces" % (sourceKey, len(targetLogs)), "debug")
           for log in targetLogs:
               tmp = log[log.rfind("/")+1:].replace(".filtered", "")
               targetKey = tmp[:tmp.find("_")]
               if not os.path.exists("%s/%s.report" % (VT_REPORTS_DIR, targetKey)):
                   prettyPrint("Could not find a \"VirusTotal\" report for \"%s\"" % targetKey, "warning")
                   continue
   
               targetLabel = getVTLabel(targetKey, labeling)
               targetTrace = parseDroidmonLog(log, includeArguments=includeArguments)
               if maxChunkSize >= 1:
                   sourceTrace = shortenDroidmonTrace(sourceTrace, maxChunkSize=maxChunkSize)
                   targetTrace = shortenDroidmonTrace(targetTrace, maxChunkSize=maxChunkSize)

               similarity = tracesRatio(targetTrace, sourceTrace) if alignTraces == False else alignDroidmonTraces(sourceTrace, targetTrace)
               if similarity >= matchingThreshold:
                   prettyPrint("Got a match between \"%s\" and \"%s\" of %s" % (targetKey, sourceKey, similarity), "output")
                   matchings.append((targetKey, (similarity, targetLabel)))

    except Exception as e:
        prettyPrintError(e)
        return []

    return matchings

def matchTwoAPKs(sourceDir, targetDir, matchingDepth=1, useSimiDroid=False):
    """
    Compares and attempts to match two APK's and returns a similarity measure
    :param sourceDir: The path to the directory containing information pre-extracted from the source APK
    :type sourceDir: str
    :param targetDir: The path to the directory containing information pre-extracted from the target APK
    :type targetDir: str
    :param matchingDepth: The depth and rigorosity of the matching (between 1 and 4)
    :type matchingDepth: int
    :param useSimiDroid: Whether to use SimiDroid to perform the comparison
    :type useSimiDroid: boolean
    :return: A float depicting the degree of similarity between two apps
    """
    try:
        similarity = 0.0
        # Retrieve information from the source APK
        if useSimiDroid == False:
            if not os.path.exists("%s/data.txt" % sourceDir) or not os.path.exists("%s/data.txt" % targetDir):
                prettyPrint("Could not locate either the source or the target directories. Returning 0.0", "warning")
                return 0.0

            sourceInfo = eval(open("%s/data.txt" % sourceDir).read())
            sourceInfo["callgraph"] = nx.read_gpickle("%s/call_graph.gpickle" % sourceDir) if os.path.exists("%s/call_graph.gpickle" % sourceDir) and matchingDepth >= 4 else None
            targetInfo = eval(open("%s/data.txt" % targetDir).read())
            targetInfo["callgraph"] = nx.read_gpickle("%s/call_graph.gpickle" % targetDir) if os.path.exists("%s/call_graph.gpickle" % targetDir) and matchingDepth >= 4 else None
            # Another sanity check
            if len(sourceInfo) < 1 or len(targetInfo) < 1:
                prettyPrint("Could not retrieve info about either the source or the target apps. Returning 0.0", "warning")
                return 0.0

            # Start the comparison
            similarities = []
            if matchingDepth >= 1:
                similarities.append(stringRatio(sourceInfo["name"], targetInfo["name"]))
                similarities.append(stringRatio(sourceInfo["package"], targetInfo["package"]))
                similarities.append(stringRatio(sourceInfo["icon"], targetInfo["icon"]))
                #differences.append(stringRatio(sourceInfo["signature"], targetInfo["signature"]))
                sourceIcon = "%s/%s" % (sourceDir, sourceInfo["icon"]) if sourceInfo["icon"] is not None else ""
                targetIcon = "%s/%s" % (targetDir, targetInfo["icon"][targetInfo["icon"].rfind('/')+1:]) if targetInfo["icon"] is not None else ""
                if os.path.exists(sourceIcon) and os.path.exists(targetIcon):
                    similarities.append(simImages(sourceIcon, targetIcon))

            if matchingDepth >= 2:
                similarities.append(listsRatio(sourceInfo["activities"], targetInfo["activities"]))
                similarities.append(listsRatio(sourceInfo["permissions"], targetInfo["permissions"]))
                similarities.append(listsRatio(sourceInfo["providers"], targetInfo["providers"]))
                similarities.append(listsRatio(sourceInfo["receivers"], targetInfo["receivers"]))
                similarities.append(listsRatio(sourceInfo["services"], targetInfo["services"]))
                similarities.append(listsRatio(sourceInfo["files"], targetInfo["files"]))

            if matchingDepth >= 3:
                similarities.append(listsRatio(sourceInfo["libraries"], targetInfo["libraries"]))
                similarities.append(listsRatio(sourceInfo["classes"], targetInfo["classes"]))
                similarities.append(listsRatio(sourceInfo["methods"], targetInfo["methods"]))

            if matchingDepth >= 4:
                isomorphic = nx.algorithms.is_isomorphic(sourceInfo["callgraph"], targetInfo["callgraph"])
                if isomorphic:
                    similarities.append(1.0)
                else:
                    similarities.append(0.0)

        else:
            # Use SimiDroid to perform comparison
            curDir = os.path.abspath(".")
            os.chdir(SIMIDROID_DIR)
            cmd = "java -jar SimiDroid.jar %s %s" % (sourceAPK, targetAPK)
            outFile = "%s-%s.json" % (sourceAPK[sourceAPK.rfind('/')+1:].replace(".apk", ""), targetAPK[targetAPK.rfind("/")+1:].replace(".apk", ""))
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            p.communicate()
            if not os.path.exists(outFile):
                prettyPrint("Could not find SimiDroid output file. Skipping", "warning")
                return 0.0
 
            outContent = json.loads(open(outFile).read())
            os.chdir(curDir)
            
        # Calculate similarity
        similarity = float(sum(similarities))/float(len(similarities)) if useSimiDroid == False else float(outContent["conclusion"]["simiScore"])
        prettyPrint("Similarity score: %s" % similarity)

    except Exception as e:
        prettyPrintError(e)
        return 0.0

    return similarity

def parseDroidmonLog(logPath, abstractArguments=False, includeArguments=True, mode="classes"):
    """
    Parses the entries in Droidmon-generated logs
    :param logPath: The path to the JSON-log generated by Droidmon
    :type logPath: str
    :param abstractArguments: Whether to abstract the arguments of methods (e.g., to "string", "integer", "hash", etc.)
    :type abstractArguments: bool
    :param includeArguments: Whether to include the method argument in the trace
    :type includeArguments: bool
    :param mode: The format of elements in the trace (e.g., class.method(args) vs. method(args))
    :type mode: str
    :return: A list depicting the trace found in the log
    """
    try:
        # Parse the droidmon log
        if not os.path.exists(logPath):
            prettyPrint("Unable to locate \"%s\"" % logPath, "warning")
            return []
            
        lines = open(logPath).read().split('\n')
        prettyPrint("Successfully retrieved %s lines from log" % len(lines), "debug")
        droidmonLines = [l for l in lines if l.lower().find("droidmon-apimonitor-") != -1]
        # Generate trace from lines
        trace = []
        for line in droidmonLines:
            tmp = line[line.find("{"):].replace('\n','').replace('\r','')
            # Extract class and method
            c, m = "", ""
            pattern = "class\":\""
            index = tmp.find(pattern)
            c = tmp[index+len(pattern):tmp.find("\"", index+len(pattern))]
            pattern = "method\":\""
            index = tmp.find(pattern)
            m = tmp[index+len(pattern):tmp.find("\"", index+len(pattern))]
            if includeArguments:
                pattern = "args\":["
                index = tmp.find(pattern)
                a = tmp[index+len(pattern):tmp.find(']', index+len(pattern))]
            # Prepare to add args
            args = "" if not includeArguments else a
            # Abstract arguments
            if abstractArguments == True:
                for regex in argumentsRegex:
                    for f in argumentsRegex[regex].findall(args):
                        args.replace(f, regex)
            # Append to trace
            if mode == "methods":
                trace.append("%s(%s)" % (m, args))
            elif mode == "classes":
                trace.append("%s.%s(%s)" % (c, m, args))
                
    except Exception as e:
        prettyPrintError(e)
        return []
        
    return trace

def prepareHMMData(includeArguments=True, labeling="vt1-vt1"):
    """
    Retrieves and parses droidmon logs and their actions to train a HMM
    :param includeArguments: Whether to include method arguments in the traces
    :type includeArguments: bool
    :param labeling: The labeling scheme to adopt in labeling the traces (default: vt1-vt1)
    :type labeling: str
    :return: Two lists depicting (1) traces, and (2) actions
    """
    try:
        traces, actions = [], []#, labels = [], [], []
        # Retrieve traces
        allLogs = glob.glob("%s/*.filtered" % LOGS_DIR)
        if len(allLogs) < 1:
            prettyPrint("Could not find any droidmon logs under \"%s\"" % LOGS_DIR, "warning")
            return [], []#, []

        prettyPrint("Successfully retrieved a total of %s logs" % len(allLogs))
        # Load traces
        for log in allLogs:
            # Retrieve the log's label according to a labeling scheme
            logLabel = -1
            tmp = log[log.rfind("/")+1:].replace(".filtered", "")
            logKey = tmp[:tmp.find("_")]
            if os.path.exists("%s/%s.report" % (VT_REPORTS_DIR, logKey)):
                report = eval(open("%s/%s.report" % (VT_REPORTS_DIR, logKey)).read())
                prettyPrint("VirusTotal report \"%s.report\" found" % logKey, "debug")
                if "positives" in report.keys():
                    if labeling == "old":
                        if "additional_info" in report.keys():
                            if "positives_delta" in report["additional_info"].keys():
                                logLabel = 1 if report["positives"] - report["additional_info"]["positives_delta"] >= 1 else 0
                        else:
                            continue
                    if labeling == "vt1-vt1":
                        logLabel = 1 if report["positives"] >= 1 else 0
                    elif labeling == "vt50p-vt50p":
                        logLabel = 1 if report["positives"]/float(report["total"]) >= 0.5 else 0
                    elif labeling == "vt50p-vt1":
                        if report["positives"]/float(report["total"]) >= 0.5:
                            logLabel = 1
                        elif report["positives"] == 0:
                            logLabel = 0
                        else:
                            logLabel = -1

            if logLabel == -1:
                prettyPrint("Could not label log \"%s\". Skipping" % log, "warning")
                continue
            elif logLabel == 1:
                prettyPrint("Log \"%s\" is malicious according to \"%s\". Skipping" % (log, labeling), "error")
                continue

            trace = parseDroidmonLog(log, includeArguments=includeArguments)
            traces.append(trace) # Add trace
            for action in trace:
                if not action in actions:
                    actions.append(action) # Add action

            # Add label
            #labels.append(logLabel)
            
    except Exception as e:
        prettyPrintError(e)
        return [], []#, []

    return traces, actions#, labels

def rgb_to_hex(rgb):
    return '%02x%02x%02x' % rgb

def simCertificateOwners(ownerA, ownerB):
    """
    Compares the issuers of two certificates
    :param ownerA: The issuer details of the first certificate
    :type ownerA: str
    :param ownerB: The issuer details of the second certificate
    :type ownerB: str
    :return: float depicting the similarity between the two issuers
    """
    try:
        # Parse two strings to extract data
        dataA, dataB = {}, {}
        delimiterA = ';' if issuerA.find('; ') != -1 else ','
        delimiterB = ';' if issuerB.find('; ') != -1 else ','
        for t in issuerA.split("%s " % delimiterA):
            if len(t) > 0:
                key, value = t.split(": ")
                dataA[key] = value

        for t in issuerB.split("%s " % delimiterB):
            if len(t) > 0:
                key, value = t.split(": ")
                dataB[key] = value

        # Gather common keys
        commonKeys = list(set.intersection(set(dataA.keys()), set(dataB.keys())))
        sims = []
        for key in commonKeys:
            sims.append(stringRatio(dataA[key], dataB[key]))
            
    except Exception as e:
        prettyPrintError(e)
        return 0.0
    
    sim = 0.0 if len(sims) < 1 else sum(sims)/float(len(sims))

    return sim

def simImages(imgA, imgB):
    """
    Compares the structure similarity of two images and retrurns the SSIM similarity
    :param imgA: The path to the first image
    :type imgA: str
    :param imgB: The path to the second image
    :type imgB: str
    :return: float depicting the SSIM similarity between the two images
    """
    try:
        # load the two input images
        imageA = cv2.imread(imgA)
        imageB = cv2.imread(imgB)
        score = -1.0
 
        # convert the images to grayscale
        grayA = cv2.cvtColor(imageA, cv2.COLOR_BGR2GRAY)
        grayB = cv2.cvtColor(imageB, cv2.COLOR_BGR2GRAY)

        # resize images in case of mismatching dimensions
        # resize smaller images to bigger ones
        if grayA.shape > grayB.shape:
            grayB.resize(grayA.size)
            grayA.resize(grayA.size)

        elif grayA.shape < grayB.shape:
            grayA.resize(grayB.size)
            grayB.resize(grayB.size)

        # compute the Structural Similarity Index (SSIM) between the two
        # images, ensuring that the difference image is returned
        (score, sim) = compare_ssim(grayA, grayB, full=True)
        sim = (sim * 255).astype("uint8")
        
        #print("SSIM: {}".format(score))
    except Exception as e:
        prettyPrintError(e)
        return 0.0      

    return score

def shortenDroidmonTrace(trace, maxChunkSize=3):
    """
    Shortens a Droidmon trace by removing redundant chunks of API calls
    :param trace: The Droidmon trace to shorten
    :type trace: list of str
    :param maxChunkSize: The maximum size of a chunk to consider (default: 3)
    :type maxChunkSize: int
    :return: A list of str depicting the shortened trace
    """ 
    try:
        # Assume maxChunkSize = 1 anyway
        shortened = []
        previousAction = ""
        for action in trace:
            if action != previousAction:
                shortened.append(action)

            previousAction = action
        # Go for chunks of length > 1
        if maxChunkSize > 1:
            for chunkSize in range(maxChunkSize, maxChunkSize+1):
                chunks = [shortened[x:x+chunkSize] for x in xrange(0, len(shortened), chunkSize)]
                tmpTrace = []
                previousChunk = []
                for chunk in chunks:
                    if chunk != previousChunk:
                        tmpTrace = tmpTrace + chunk

                    previousChunk = chunk

                # Update the shortened trace
                shortened = [] + tmpTrace

    except Exception as e:
        prettyPrintError(e)
        return []

    return shortened

def summarizeVirusTotalData(vtReport):
    """
    Summarizes the runtime behavior exhibited by an app according to VirusTotal
    :param vtReport: The path to the VirusTotal report to summarize
    :type data: str
    :return: A tuple of (str, list[int...]) depicting the key of the report (e.g., hash), and a vector of numerical values depicting the counts of different keys (e.g., accessed files)
    """
    try:
        summary = ()
        report = eval(open(vtReport).read())
        reportKey = vtReport[vtReport.rfind("/")+1:].replace(".report", "")
        reportVector = [0.0] * len(allVirusTotalKeys)
        for key in allVirusTotalKeys:
            if key in report["additional_info"]["android-behaviour"] and key != "sandbox-version":
                reportVector[allVirusTotalKeys.index(key)] = len(report["additional_info"]["android-behaviour"][key])

        summary = (reportKey, reportVector)

    except Exception as e:
        prettyPrintError(e)
        return ()

    return summary

def tracesRatio(trace1, trace2):
    if len(trace1) == 0 or len(trace2) == 0:
        return 0.0

    intersection = float(len(list(set(trace1).intersection(trace2))))
    union = float((len(set(trace1)) + len(set(trace2))) - intersection)
    return float(intersection / union)

