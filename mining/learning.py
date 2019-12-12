#!/usr/bin/python

from Maat.utils.graphics import *
from Maat.shared.constants import *
from Maat.conf.config import *
from Maat.utils.misc import *
from Maat.mining import correctness, evolution, misc
from Maat.learning.scikit_learners import calculateMetrics

from sklearn import tree, svm, ensemble
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import RandomizedSearchCV
from sklearn.metrics import *

from numpy import mean, median, std
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import randint as sp_randint
import pickle

if not sys.warnoptions:
    import warnings
    warnings.simplefilter("ignore")


def extractEngineeredFeatures(maliciousDatasetDir, benignDatasetDir, vtReportsDirs):
    """
    Extracts features from the VirusTotal reports of the malicious and benign apps
    :param maliciousDatasetDir: The list of malicious apps or the directory containing their APK archives
    :type maliciousDatasetDir: list or str
    :param benignDatasetDir: The list of benign apps or the directory containing their APK archives
    :type benignDatasetDir: list or str
    :param vtReportsDirs: The directories containing the VirusTotal scan reports of malicious and benign apps
    :type vtReportsDirs: list or str
    :return: Three lists containing the feature vectors extracted from the scan reports, their labels, and descriptions of the extract features
    """
    try:
        X, y = [], []
        # Retrieve apps, first and foremost
        maliciousApps = maliciousDatasetDir if type(maliciousDatasetDir) == list else glob.glob("%s/*.apk" % maliciousDatasetDir)
        benignApps = benignDatasetDir if type(benignDatasetDir) == list else  glob.glob("%s/*.apk" % benignDatasetDir)
        if len(maliciousApps) < 1:
            prettyPrint("Could not retrieve malicious APK's from \"%s\"" % maliciousDatasetDir, "warning")
            return [], [], []

        if len(benignApps) < 1:
            prettyPrint("Could not retrieve benign APK's from \"%s\"" % benignDatasetDir, "warning")
            return [], [], []

        # Retrieve the list of directories
        vtDirs = vtReportsDirs if type(vtReportsDirs) == list else glob.glob(vtReportsDirs)

        # Remove benign apps with positives >= 1 (according to the latest VirusTotal reports)
        if VERBOSE == "ON":
            prettyPrint("Filtering benign apps", "debug")

        for app in benignApps:
            if os.path.exists("%s/%s.report" % (vtDirs[-1], app[app.rfind("/")+1:].replace(".apk", ""))):
                report = eval(open("%s/%s.report" % (vtDirs[-1], app[app.rfind("/")+1:].replace(".apk", ""))).read())
                if report["positives"] > 0:
                    benignApps.remove(app)
            else:
                benignApps.remove(app)

        if VERBOSE == "ON":
            prettyPrint("Benign apps reduced to %s apps" % len(benignApps), "debug")

        # Get the most correct scanners for malicious apps
        # It does not make sense to do the same for benign apps especially since we pick apps with positives = 0
        # So, all scanners will agree upon the nature of such apps as being benign returning all scanners as most correct
        prettyPrint("Getting the most correct scanners over time for malicious apps")
        maliciousGroundTruth = {"%s" % app[app.rfind("/")+1:].replace(".apk", ""): 1.0 for app in maliciousApps}
        mostCorrectScanners = correctness.getMostCorrectScannersOverTime(maliciousApps, vtDirs, maliciousGroundTruth)
        mostCorrectScanners.sort() # Sort alphabetically (just for pretty printing)
        if VERBOSE == "ON":
            prettyPrint("The most consistently correct scanners are: %s" % ", ".join(mostCorrectScanners), "debug")
       
        # Filter such scanners to make sure they are stable within the given time period
        prettyPrint("Filtering most correct scanners to get most stable ones between \"%s\" and \"%s\"" % (vtDirs[0][vtDirs[0].rfind("/")+1:], vtDirs[-1][vtDirs[-1].rfind("/")+1:]))
        filteredMaliciousScanners = evolution.getStableScanners(maliciousApps, vtDirs, mostCorrectScanners).keys()
        filteredMaliciousScanners.sort()
        if VERBOSE == "ON":
            prettyPrint("The most stable scanners on malicious apps are: %s" % ", ".join(filteredMaliciousScanners), "debug")

        # Do the same for benign apps
        prettyPrint("Are those scanners also stable for benign apps?")
        filteredBenignScanners = evolution.getStableScanners(benignApps, vtDirs, filteredMaliciousScanners).keys()
        filteredScanners = list(set(filteredBenignScanners).intersection(set(filteredMaliciousScanners)))
        filteredScanners.sort()
        if VERBOSE == "ON":
            prettyPrint("The intersection between filtered malicious and benign scanners is : %s" % ", ".join(filteredScanners), "debug")

        # We have our lest of "elite" scanners. Now extract features from apps
        features = filteredScanners + ["Age", "Times Submitted", "Positives", "Total"] + all_permissions + all_tags
        X, y = [], []             

        allApps = maliciousApps + benignApps
        for app in allApps:
            key = app[app.rfind("/")+1:].replace(".apk", "")
            prettyPrint("Extracting features from \"%s\", #%s, out of %s" % (key, allApps.index(app), len(allApps)))
            x = []                          
            report = eval(open("%s/%s.report" % (vtDirs[-1], key)).read())
            # Scanners
            for scanner in filteredScanners:
                if scanner in report["scans"].keys():
                    label = 1.0 if report["scans"][scanner]["detected"] == 1.0 else 0.0
                    x.append(label)
                else:
                    x.append(-1.0)
            # Misc stuff
            first_seen = datetime.strptime(report["first_seen"], "%Y-%m-%d %H:%M:%S")
            today = datetime.fromtimestamp(time.time())
            age = (today - first_seen).days / 360.0
            x.append(age)
            x.append(report["times_submitted"])
            x.append(report["positives"])
            x.append(report["total"])
            # Permissions
            if "additional_info" in report.keys():
                if "androguard" in report["additional_info"].keys():
                    if "Permissions" in report["additional_info"]["androguard"].keys():
                        for p in all_permissions:
                            if p in report["additional_info"]["androguard"]["Permissions"].keys():
                                x.append(1.0)
                            else:
                                x.append(0.0)
                    else:
                        x += [0.0]*len(all_permissions)
                else:
                    x += [0.0]*len(all_permissions)
            else:
                x += [0.0]*len(all_permissions)

            # Lastly tags
            for t in all_tags:
                if t in report["tags"]:
                    x.append(1.0)
                else:
                    x.append(0.0)
                  
            X.append(x)
            label = 1.0 if app in maliciousApps else 0.0
            y.append(label)

    except Exception as e:
        prettyPrintError(e)
        return [], [], []

    return X, y, features

def extractNaiveFeatures(maliciousDatasetDir, benignDatasetDir, vtReportsDir):
    """
    Extracts features from the VirusTotal reports of the malicious and benign apps
    :param maliciousDatasetDir: The list of malicious apps or the directory containing their APK archives
    :type maliciousDatasetDir: list or str
    :param benignDatasetDir: The list of benign apps or the directory containing their APK archives
    :type benignDatasetDir: list or str
    :param vtReportsDirs: The directory containing the VirusTotal scan reports of malicious and benign apps
    :type vtReportsDirs: str
    :return: Two lists containing the feature vectors extracted from the scan reports and their labels
    """
    try:
        maliciousApps = glob.glob("%s/*.apk" % maliciousDatasetDir)
        benignApps = glob.glob("%s/*.apk" % benignDatasetDir)
        maliciousApps.sort() # Sort alphabetically
        benignApps.sort()
        if len(maliciousApps) < 1 or len(benignApps) < 1:
            prettyPrint("Could not retrieve malicious or benign apps from \"%s\" and \"%s\"" % (maliciousDatasetDir, benignDatasetDir), "warning")
            return [], []

        Xmal, Xben, ymal, yben = [], [], [], []
        # Retrieve all feature vectors and labels
        for app in maliciousApps + benignApps:
            key = app[app.rfind("/")+1:].replace(".apk", "")
            prettyPrint("Processing app \"%s\", #%s out of %s" % (key, (maliciousApps+benignApps).index(app), len(maliciousApps+benignApps)))
            if os.path.exists("%s/%s.report" % (vtReportsDir, key)):
                report = eval(open("%s/%s.report" % (vtReportsDir, key)).read())
                x = [-1] * len(all_scanners)
                # Populate the feature vector
                for index in range(len(all_scanners)):
                    if all_scanners[index] in report["scans"].keys():
                        label = 1.0 if report["scans"][all_scanners[index]]["detected"] == True else 0.0
                        x[index] = label
                # Retrieve the label
                if app in benignApps:
                    if report["positives"] != 0:
                        prettyPrint("Skipping benign app \"%s\" with positives=%s" % (key, report["positives"]), "warning")
                        continue

                    yben.append(0.0)
                    Xben.append(x)
                else:
                    ymal.append(1.0)
                    Xmal.append(x)

    except Exception as e:
        prettyPrintError(e)
        return [], []


    return Xmal+Xben, ymal+yben


def labelAppsUsingModel(X, y, testDatasetDir, testVTReportsDir, featureNames, groundTruth, saveClassifier=None, useBestEstimator=None, usedClassifier="forest"):#, visualizeTree=False):
    """
    Trains a labeling tree and labels apps in a test dataset according to their VirusTotal scan reports
    :param X: The feature vectors to use to train the labeling tree
    :type X: list
    :param y: The labels of the feature vectors in X
    :type y: list
    :param testDatasetDir: The path to the directory containing the APK archives of apps in the test dataset
    :type testDatasetDir: str
    :param testVTReportsDir: The path to the directory containing the VirusTotal scan reports of apps in the test dataset
    :type testVTReportsDir: str
    :param featureNames: The names of features in the feature vectors (used for visualization) (default: [])
    :type featureNames: list
    :param groundTruth: A structure containing the ground truth of apps in the test dataset
    :type groundTruth: dict (keys: sha256 hashes of apps, values: 1.0 for malicious, 0.0 for benign)
    :param saveClassifier: The name of the best classifier to save (default: None = do NOT save)
    :type saveClassifier: str
    :param useBestEstimator: Whether to search for and use the best estimator (default: None), options: GridSearch and RandomSearch
    :type useBestEstimator: str
    :param usedClassifier: The classifier to use label apps according to their VirusTotal scan reports
    :type usedClassifier: str
    :return: A dict containing a summary of the labeler's performance and the path to the visualized tree (str)
    """
    try:
        # Retrieve the test apps
        testApps = glob.glob("%s/*.apk" % testDatasetDir)
        if len(testApps) < 1:
             prettyPrint("Could not find APK archives under \"%s\"" % testDatasetDir, "warning")
             return [], ""
       
        testApps.sort()
        truth = [groundTruth[app[app.rfind("/")+1:].replace(".apk", "")] for app in testApps]
        predicted = []
        filePath = ""
        # Build the classifier
        if usedClassifier == "bayes":
            clf = clf = GaussianNB()
        elif usedClassifier == "knn":
            clf = KNeighborsClassifier(n_neighbors=5)
        else:
            clf = ensemble.RandomForestClassifier(n_estimators=100, random_state=0)

        # Using grid/random search to select the best classifier parameters
        if useBestEstimator == None:
            prettyPrint("Training the classifier")
            clf.fit(X, y)
            labeler = clf
        elif useBestEstimator == "GridSearch":
            prettyPrint("Using GridSearchCV to find the best classifier")
            if usedClassifier == "bayes":
                param_grid = {} # The two variables to use are priors (don't have that) and var_smoothing
            elif usedClassifier == "knn":
                param_grid = {"n_neighbors": [1, 3, 5, 11, 51, 101, 501, 1001], "weights": ["uniform", "distance"], "p": [1, 2, 3]}
            else:
                features = [3, 5, 10, None]#range(1, len(X[0])+1, 2) + [None]
                param_grid = {"criterion": ["gini", "entropy"], "max_depth": [1, 4, 10, None], "max_features": features, "min_samples_split": [2, 3, 10], "bootstrap": [True, False]}
            # Commence the GridSearch
            grid_search = GridSearchCV(clf, param_grid=param_grid, cv=10, iid=False)
            grid_search.fit(X, y)
            labeler = grid_search.best_estimator_
            
        else:
            prettyPrint("Using RandomSearchCV to find the best classifier")
            # specify parameters and distributions to sample from
            if usedClassifier == "bayes":
                param_dist = {}
            elif usedClassifier == "knn":
                param_dist = {"n_neighbors": [1, 3, 5, 11, 51, 101, 501, 1001], "weights": ["uniform", "distance"], "p": [1, 2, 3]}
            else:
                features = [3, 5, 10, None]#range(1, len(X[0])+1, 2) + [None]
                param_dist = {"criterion": ["gini", "entropy"], "max_depth": [1, 4, 10, None], "max_features": features, "min_samples_split": [2, 3, 10], "bootstrap": [True, False]}

            # Commence the RandomSearch
            if usedClassifier == "bayes":
                n_iter_search = 1
            elif usedClassifier == "knn":
                n_iter_search = 1
                for key in param_dist:
                    n_iter_search *= len(param_dist[key])
            else:
                n_iter_search = 100


            random_search = RandomizedSearchCV(clf, param_distributions=param_dist, n_iter=n_iter_search, cv=10, iid=False)
            random_search.fit(X, y)
            labeler = random_search.best_estimator_

        # Save the classifier and its parameters if instructed to
        if saveClassifier != None:
            clfFile = "./%s.txt" % saveClassifier
            open(clfFile, "w").write(pickle.dumps(labeler))

        
        # Predict using the trained tree
        for app in testApps:
            key = app[app.rfind("/")+1:].replace(".apk", "")
            prettyPrint("Processing \"%s\", #%s out of %s" % (key, testApps.index(app), len(testApps)))
            if os.path.exists("%s/%s.report" % (testVTReportsDir, key)):
                report = eval(open("%s/%s.report" % (testVTReportsDir, key)).read())
                x = []
                for feature in featureNames:
                    if feature in all_scanners:
                        # It's a scanner feature
                        if feature in report["scans"].keys():
                            label = 1.0 if report["scans"][feature]["detected"] == True else 0.0
                        else:
                            label = -1.0

                        x.append(label)

                    elif feature.lower() == "age":
                        first_seen = datetime.strptime(report["first_seen"], "%Y-%m-%d %H:%M:%S")
                        today = datetime.fromtimestamp(time.time())
                        age = (today - first_seen).days / 360.0
                        x.append(age)
 
                    elif feature.lower() == "positives":
                        x.append(report["positives"])
 
                    elif feature.lower() == "total":
                        x.append(report["total"])

                    elif feature.lower().find("submitted") != -1:
                        x.append(report["times_submitted"])
  
                    elif feature in all_permissions:
                        # It's a permission feature
                        if "additional_info" in report.keys():
                            if "androguard" in report["additional_info"]:
                                if feature in report["additional_info"]["androguard"]["Permissions"]:
                                    x.append(1.0)
                                else:
                                    x.append(0.0)
                            else:
                                x.append(0.0)
                        else:
                            x.append(0.0)
 
                    elif feature in all_tags:
                        # It's a tag feature
                        if feature in report["tags"]:
                            x.append(1.0)
                        else:
                            x.append(0.0)
             
                # Predict the label of the feature vector
                p = labeler.predict(x)
                predicted.append(p)
 
        # Print results
        if len(predicted) != len(truth):
               prettyPrint("The dimensions of the predicted and ground truth vectors are different", "warning")
               return [], ""
            
        acc = accuracy_score(truth, predicted)
        recall = recall_score(truth, predicted)
        spec = specificity(truth, predicted)
        mcc = matthews_corrcoef(truth, predicted)
        prettyPrint("Accuracy = %s" % acc, "info2")
        prettyPrint("Recall = %s" % recall, "info2")
        prettyPrint("Specificity = %s" % spec, "info2")
        prettyPrint("MCC = %s" % mcc, "info2")
 
        #if visualizeTree == True:
        #    # Save the trained labeler as PDF
        #    prettyPrint("Visualizing and saving labeling tree")
        #    from sklearn.tree import export_graphviz
        #    figurePath = "./engineeredFeatures_tree.dot"
        #    export_graphviz(labeler, out_file=figurePath, feature_names = featureNames, class_names=["Benign", "Malicious"], rounded = True, proportion = False, filled = True)
        #    from subprocess import call
        #    call(['dot', '-Tpng', figurePath, '-o', figurePath.replace(".dot", ".png"), '-Gdpi=600'])
        

    except Exception as e:
        prettyPrintError(e)
        return [], ""


    return calculateMetrics(truth, predicted), filePath

def labelAppsUsingThreshold(datasetDir, vtReportsDirs, groundTruth, labelingSchemes):
    """
    Calculates the accuracy of different labeling schemes in predicting the correct labels of apps in a dataset
    :param datasetDir: The directory containing the APK's in the dataset
    :type datasetDir: str
    :param vtReportsDirs: The directories containing the VirusTotal scan reports of the apps in the dataset
    :type vtReportsDirs: list or str
    :param groundTruth: The ground truth of the apps in the dataset
    :type groundTruth: dict (key: str, value: float)
    :param labelingSchemes: A list of threshold-based labeling schemes
    :type labelingSchemes: list
    :return: Three dicts with keys depicting the labeling schemes and values as (a) lists of apps correctly labeled, and (b) predicted labels, and (c) summary of metrics
    """
    try:
        correct, predicted = {}, {}
        # Retrieve the list of directories
        vtDirs = vtReportsDirs if type(vtReportsDirs) == list else glob.glob(vtReportsDirs)
        # Retrieve and iterate over the apps
        allApps = glob.glob("%s/*.apk" % datasetDir)
        allApps.sort()
        if len(allApps) < 1:
            prettyPrint("Could not retrieve any apps from \"%s\"" % datasetDir, "warning")
            return {}, {}
  
        truth = [groundTruth[app[app.rfind("/")+1:].replace(".apk", "")] for app in allApps]
        truth_vt50pvt1 = []
        for app in allApps:
            key = app[app.rfind("/")+1:].replace(".apk", "")
            if VERBOSE == "ON":
                prettyPrint("Processing \"%s\", #%s out of %s" % (key, allApps.index(app)+1, len(allApps)), "debug")
 
            for vtDir in vtDirs:
                dirKey = vtDir[vtDir.rfind("_")+1:].replace("/", "")
                if os.path.exists("%s/%s.report" % (vtDir, key)):
                    report = eval(open("%s/%s.report" % (vtDir, key)).read())
                    for scheme in labelingSchemes:
                        if scheme < 1.0:
                            # Assume precentage-based threshold
                            label = 1.0 if report["positives"]/float(report["total"]) >= scheme else 0.0
                        elif scheme == "drebin":
                            counter = 0.0
                            for scanner in drebin_scanners:
                                if scanner in report["scans"].keys():
                                    if report["scans"][scanner]["detected"] == True:
                                        counter += 1.0
                            label = 1.0 if counter >= 2.0 else 0.0
                        elif scheme == "vt50pvt1":
                            if report["positives"]/float(report["total"]) >= 0.5:
                                label = 1.0
                            else:
                                label = -1.0 if report["positives"] != 0 else 0.0
                            if label != -1.0:
                                truth_vt50pvt1.append(groundTruth[key])

                        else:
                            # Assume integer-based threshold
                            label = 1.0 if report["positives"] >= scheme else 0.0

                        if key in groundTruth.keys():
                            if not "vt-%s_%s" % (scheme, dirKey) in predicted.keys():
                                predicted["vt-%s_%s" % (scheme, dirKey)] = []

                            if label != -1.0:
                                predicted["vt-%s_%s" % (scheme, dirKey)].append(label)
                                # Is it correct according to the ground truth?
                                if groundTruth[key] == label:
                                    if not "vt-%s_%s" % (scheme, dirKey) in correct.keys():
                                        correct["vt-%s_%s" % (scheme, dirKey)] = []
                                    correct["vt-%s_%s" % (scheme, dirKey)].append(key)


        # Print results
        keys = correct.keys()
        keys.sort()
        metrics = {}

        for key in keys:
            tmp_truth = [] + truth_vt50pvt1 if key.find("vt50pvt1") != -1 else truth
            metrics[key] = calculateMetrics(tmp_truth, predicted[key])
            prettyPrint("Results for \"%s\", correctness = %s" % (key, round(len(correct[key])/float(len(allApps)), 2)), "output")
            prettyPrint("Accuracy for \"%s\" = %s" % (key, accuracy_score(tmp_truth, predicted[key])), "info2")
            prettyPrint("Recall for \"%s\" = %s" % (key, recall_score(tmp_truth, predicted[key])), "info2")
            prettyPrint("Specificity for \"%s\" = %s" % (key, specificity(tmp_truth, predicted[key])), "info2")
            prettyPrint("MCC for \"%s\" = %s" % (key, matthews_corrcoef(tmp_truth, predicted[key])), "debug")

    except Exception as e:
        prettyPrintError(e)
        return {}, {}, {}

    return correct, predicted, metrics

def learnUsingNaiveFeatures(maliciousDatasetDir, benignDatasetDir, vtReportsDirs, rollingLearning=[]):
    """
    Builds a labeling decision trees using naive features extracted from VirusTotal reports of apps in different datasets (e.g., malicious and benign)
    :param maliciousDatasetDir: The directory containing the malicious apps
    :type maliciousDatasetDir: str
    :param benignDatasetDir: The directory containing the benign apps
    :type benignDatasetDir: str
    :param vtReportsDirs: The directories containing the VirusTotal reports (Should have any trace of date in the name e.g., vt_reports_2015)
    :type vtReportsDirs: list (OR) str
    :param rollingLearning: Whether to incrementally consider a subset of apps in the benign and malicious datasets to train the apps
    :return: A list of tuple's of (sklearn.tree.tree.DecisionTreeClassifier, str) containing an object of the trained decision tree and its description
    """
    try:
        maliciousApps = glob.glob("%s/*.apk" % maliciousDatasetDir)
        benignApps = glob.glob("%s/*.apk" % benignDatasetDir)
        maliciousApps.sort() # Sort alphabetically
        benignApps.sort()
        if len(maliciousApps) < 1 or len(benignApps) < 1:
            prettyPrint("Could not retrieve malicious or benign apps from \"%s\" and \"%s\"" % (maliciousDatasetDir, benignDatasetDir), "warning")
            return []
  
        # Retrieve the list of directories
        vtDirs = vtReportsDirs if type(vtReportsDirs) == list else glob.glob(vtReportsDirs)

        trainedTrees = []
        for vtDir in vtDirs:
            prettyPrint("Processing reports directory \"%s\"" % vtDir)

            Xmal, Xben, ymal, yben = [], [], [], []
            # Retrieve all feature vectors and labels
            for app in maliciousApps + benignApps:
                key = app[app.rfind("/")+1:].replace(".apk", "")
                prettyPrint("Processing app \"%s\", #%s out of %s" % (key, (maliciousApps+benignApps).index(app), len(maliciousApps+benignApps)))
                if os.path.exists("%s/%s.report" % (vtDir, key)):
                    report = eval(open("%s/%s.report" % (vtDir, key)).read())
                    x = [-1] * len(all_scanners)
                    # Populate the feature vector
                    for index in range(len(all_scanners)):
                        if all_scanners[index] in report["scans"].keys():
                            label = 1.0 if report["scans"][all_scanners[index]]["detected"] == True else 0.0
                            x[index] = label
                    # Retrieve the label
                    if app in benignApps:
                        if report["positives"] != 0:
                            prettyPrint("Skipping benign app \"%s\" with positives=%s" % (key, report["positives"]), "warning")
                            continue

                        yben.append(0.0)
                        Xben.append(x)
                    else:
                        ymal.append(1.0)
                        Xmal.append(x)

            # Now train the tree according to the rolling learning
            if len(rollingLearning) == 0:
                prettyPrint("Training labeling tree with %s malicious apps and %s benign apps" % (len(Xmal), len(Xben)))
                labeler = tree.DecisionTreeClassifier()
                labeler.fit(Xmal+Xben, ymal+yben)
                timestamp = vtDir[vtDir.rfind("_")+1:].replace("/", "")
                trainedTrees.append((labeler, "%s_full" % timestamp))
            else:
                for count in rollingLearning:
                    if count > len(Xmal) or count > len(Xben):
                        prettyPrint("Cannot train labeling tree with %s benign and malicious apps" % count, "warning")
                        continue

                    prettyPrint("Training labeling tree with %s malicious and benign apps" % count)
                    labeler = tree.DecisionTreeClassifier()
                    labeler.fit(Xmal[:count]+Xben[:count], ymal[:count]+yben[:count])
                    timestamp = vtDir[vtDir.rfind("_")+1:].replace("/", "")
                    trainedTrees.append((labeler, "%s_%s" % (timestamp, count)))
                # And now the full corpus
                labeler = tree.DecisionTreeClassifier()
                labeler.fit(Xmal+Xben, ymal+yben)
                timestamp = vtDir[vtDir.rfind("_")+1:].replace("/", "")
                trainedTrees.append((labeler, "%s_full" % timestamp))


    except Exception as e:
        prettyPrintError(e)
        return []

    return trainedTrees

# Utility function to report best scores
# Taken from: https://scikit-learn.org/stable/auto_examples/model_selection/plot_randomized_search.html
def report(results, n_top=3):
    for i in range(1, n_top + 1):
        candidates = np.flatnonzero(results['rank_test_score'] == i)
        for candidate in candidates:
            print "Model with rank: {0}".format(i)
            print "Mean validation score: {0:.3f} (std: {1:.3f})".format(results['mean_test_score'][candidate], results['std_test_score'][candidate])
            print "Parameters: {0}".format(results['params'][candidate])
            print ""
    
def selectFeatures(X, y, featureNames=[], selectionModel="RF"):
    """
    Selects most informative features from a feature set
    :param X: The matrix containing the feature vectors
    :type X: 2-d list of int's/float's
    :param y: The labels of the feature vectors in X
    :type y: list of float's/int's
    :param featureNames: Descriptions of the features in the feature vectors (default: [])
    :type featureNames: list of str's
    :param selectionModel: The algorithm SelectFromModel should use to select the features (default: RF = Random Forests)
    :type selectionModel: str
    :return: Three lists depicting the (1) the reducted feature vectors, (2) the labels, and (3) the descriptions of the selected features
    """
    try:
        # Some sanity checks
        if len(X) < 1 or len(y) < 1 or len(X) != len(y):
            prettyPrint("There's some issue with the shapes of X and y", "warning")
            return [], [], []

        X, y = np.array(X), np.array(y)
        Xnew, newFeatures = [], []

        clf = svm.LinearSVC(C=0.01, penalty="l1", dual=False) if selectionModel == "SVM" else ensemble.ExtraTreesClassifier(n_estimators=100, random_state=0)
        # Fit model
        prettyPrint("Fitting a \"%s\" classifier" % selectionModel)
        clf.fit(X, y)

        # Select features
        prettyPrint("Processing feature vectors of dimension %s" % X[0].shape[0])
        model = SelectFromModel(clf, prefit=True)
        Xnew = model.transform(X)
        prettyPrint("The new dimension of feature vectors is %s" % Xnew[0].shape[0], "output") 

        # Get the new features
        mask = model.get_support()
        for bool, feature in zip(mask, featureNames):
            if bool:
                newFeatures.append(feature)

    except Exception as e:
        prettyPrintError(e)
        return [], [], []

    return Xnew.tolist(), y.tolist(), newFeatures

