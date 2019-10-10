#!/usr/bin/python

import warnings

from Maat.conf.config import *
from Maat.utils.graphics import *
from Maat.utils.data import *
from Maat.learning.feature_extraction import *
from Maat.learning.scikit_learners import *
from Maat.shared.constants import *
from Maat.mining import correctness, evolution, malignancy, misc, learning
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.svm import LinearSVC
from sklearn.naive_bayes import GaussianNB

import matplotlib
import matplotlib.pyplot as plt
import numpy as np

import pickle
from Levenshtein import distance
import ghmm
import argparse, os, glob, random, sys, operator, logging, shutil, time, signal
from exceptions import KeyError
if not sys.warnoptions:
    import warnings
    warnings.simplefilter("ignore")

def defineArguments():
    parser = argparse.ArgumentParser(prog="Maat_tool.py", description="Utilizes the Maat API to mine VirusTotal reports and return insights about them.")
    parser.add_argument("-t", "--task", help="The task to accomplish after analyzing the VirusTotal reports", required=True, choices=["naive_experiments", "advanced_experiments"])
    parser.add_argument("-m", "--maliciousdir", help="The directory containing the malicious APKs (naive_experiments)", required=False)
    parser.add_argument("-b", "--benigndir", help="The directory containing the benign APKs (naive_experiments)", required=False)
    parser.add_argument("-d", "--vtreportsdirs", help="The directories containing the VirusTotal reports (both experiments)", required=True, nargs='+')
    parser.add_argument("-y", "--trainingdatasetdir", help="The directory containing the feature vectors to use to train classifiers to assess a pre-trained labeler (advanced_experiments)", required=False)
    parser.add_argument("-x", "--testdatasetdir", help="The directory containing the feature vectors of the test APK's (both experiments)", required=True)
    parser.add_argument("-e", "--fileext", help="The extension of the feature vector files", required=False, default="apk")
    parser.add_argument("-v", "--testvtreportsdir", help="The directory containing the VirusTotal reports of the test apps (both experiments)", required=True)
    parser.add_argument("-g", "--testgroundtruth", help="The CSV file containing the ground truth of apps in the test dataset (both experiments)", required=True)
    parser.add_argument("-f", "--featurestype", help="The type of features to extract from the training dataset", required=False, default="both", choices=["naive", "engineered", "both"])
    parser.add_argument("-c", "--labelingclassifier", help="The classifier to use to label apps (naive_experiments)", required=False, default="forest", choices=["forest", "bayes", "knn"])
    parser.add_argument("-n", "--classifiername", help="The name to give to the saved labeling classifier (naive_experiments)", required=False, default="labeler")
    parser.add_argument("-s", "--searchstrategy", help="The strategy used to find the best estimator for tree-based labeling (naive_experiments)", required=False, default="GridSearch", choices=["GridSearch", "RandomSearch"])
    parser.add_argument("-o", "--savedlabeler", help="The labeler you wish to use to label apps in a dataset (advanced experiments)", required=False, default="./labeler.txt")
    parser.add_argument("-l", "--trainingclassifier", help="The type of classifier to train using the training feature vectors (advanced experiments). Examples: KNN-5, DREBIN, FOREST-10, SVM, GNB, TREE", required=False, default="TREE")
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Yalla beena!!")
        
        logging.disable(50)
        # Retrieve the apps to be tested
        testApps = glob.glob("%s/*.%s" % (arguments.testdatasetdir, arguments.fileext))
        if len(testApps) < 1:
            prettyPrint("Could not retrieved apps to test", "warning")
            return False

        #print arguments.vtreportsdirs
        #return True

        if arguments.task == "naive_experiments":
            # The first set of experiments is concerned with labeling apps using different threshold- and RF-based labelers
            prettyPrint("Commencing naive experiments")
            # Engineered features
            if not arguments.featurestype == "naive":
            # Do the heavy lifting first and extract naive and engineered features
                if VERBOSE == "ON":
                    prettyPrint("Extracting engineered features", "debug")

                Xeng, yeng, features = learning.extractEngineeredFeatures(arguments.maliciousdir, arguments.benigndir, arguments.vtreportsdirs)
                open("./%s_%s_%s_eng_full_features.txt" % (arguments.classifiername, arguments.labelingclassifier, arguments.searchstrategy.lower()), "w").write(str(features))
          
            # Select features from the feature vectors using RF
                XengSelected, yengSelected, featuresSelected = learning.selectFeatures(Xeng, yeng, features)
                open("./%s_%s_%s_eng_selected_features.txt" % (arguments.classifiername, arguments.labelingclassifier, arguments.searchstrategy.lower()), "w").write(str(featuresSelected))

            # Now the naive features
            if not arguments.featurestype == "engineered":
                if VERBOSE == "ON":
                    prettyPrint("Extracting the naive features", "debug")
                vtDirs = arguments.vtreportsdirs
                vtDirs.sort()

                Xnaive, ynaive = learning.extractNaiveFeatures(arguments.maliciousdir, arguments.benigndir, vtDirs[-1])
                # Select features from the naive vectors using RF and SVM as well
                XnaiveSelected, ynaiveSelected, featuresNaiveSelected = learning.selectFeatures(Xnaive, ynaive, all_scanners)
                open("./%s_%s_%s_naive_selected_features.txt" % (arguments.classifiername, arguments.labelingclassifier, arguments.searchstrategy.lower()), "w").write(str(featuresNaiveSelected))
            
            # Commence the labeling of the test dataset
            # Start with thresholds
            content = open(arguments.testgroundtruth).read().split('\n')
            testGroundTruth = {}
            for line in content:
                if line.lower().find("label") == -1 and len(line) > 0:
                    key, label = line.split(',')[0], float(line.split(',')[3])
                    testGroundTruth[key] = label

            prettyPrint("Labeling apps in the test dataset using threshold-based labeling strategies")    
            correctThreshold, predictedThreshold, predictedMetrics = learning.labelAppsUsingThreshold(arguments.testdatasetdir, arguments.testvtreportsdir, testGroundTruth, [1, 4, 10, "drebin", 0.5])

            # Now the tree-based labeling strategies
            # Engineered Features
            classifierName = arguments.classifiername
            if not arguments.featurestype == "naive":
                metricsEngFull = learning.labelAppsUsingModel(Xeng, yeng, arguments.testdatasetdir, arguments.testvtreportsdir, features, testGroundTruth, useBestEstimator=arguments.searchstrategy, usedClassifier=arguments.labelingclassifier, saveClassifier=classifierName + "_%s_%s_eng_full" % (arguments.labelingclassifier, arguments.searchstrategy.lower()))

                metricsEngSelected = learning.labelAppsUsingModel(XengSelected, yengSelected, arguments.testdatasetdir, arguments.testvtreportsdir, featuresSelected, testGroundTruth, useBestEstimator=arguments.searchstrategy, usedClassifier=arguments.labelingclassifier, saveClassifier=classifierName + "_%s_%s_eng_selected" % (arguments.labelingclassifier, arguments.searchstrategy.lower()))

            # Naive features
            if not arguments.featurestype == "engineered":
                metricsNaiveFull = learning.labelAppsUsingModel(Xnaive, ynaive, arguments.testdatasetdir, arguments.testvtreportsdir, all_scanners, testGroundTruth, useBestEstimator=arguments.searchstrategy, usedClassifier=arguments.labelingclassifier, saveClassifier=classifierName + "_%s_%s_naive_full" % (arguments.labelingclassifier, arguments.searchstrategy.lower()))

                metricsNaiveSelected = learning.labelAppsUsingModel(XnaiveSelected, ynaiveSelected, arguments.testdatasetdir, arguments.testvtreportsdir, featuresNaiveSelected, testGroundTruth, useBestEstimator=arguments.searchstrategy, usedClassifier=arguments.labelingclassifier, saveClassifier=classifierName + "_%s_%s_naive_selected" % (arguments.labelingclassifier, arguments.searchstrategy.lower()))
 

        elif arguments.task == "advanced_experiments":
            # Sort the VirusTotal dirs
            vtDirs = arguments.vtreportsdirs
            vtDirs.sort()
            trainingApps = glob.glob("%s/*.%s" % (arguments.trainingdatasetdir, arguments.fileext))
            if len(trainingApps) < 1:
                prettyPrint("Could not load feature vectors with extention \".%s\" from \"%s\"" % (arguments.fileext, arguments.trainingdatasetdir), "error")
                return False

            prettyPrint("Successfully retrieved %s feature vector files" % (len(trainingApps)))

            # Load the labeling classifier
            if VERBOSE == "ON":
                prettyPrint("Loading the labeler from \"%s\"" % arguments.savedlabeler, "debug")

            labeler = pickle.loads(open(arguments.savedlabeler).read())
            features = all_scanners if arguments.savedlabeler.find("naive_full") != -1 else eval(open(arguments.savedlabeler.replace(".txt", "_features.txt")).read())

            X, X_vt50p1 = [], []
            y, y_vt1, y_vt4, y_vt10, y_vt50p, y_vt50p1, y_drebin = [], [], [], [], [], [], []
            prettyPrint("Extracting features from the training dataset's VirusTotal reports")
            for app in trainingApps:
                key = app[app.rfind("/")+1:].replace(".%s" % arguments.fileext, "")
                x = eval(open(app).read())
                x_label = []
                if os.path.exists("%s/%s.report" % (vtDirs[-1], key)):
                    report = eval(open("%s/%s.report" % (vtDirs[-1], key)).read())
                    for f in features:
                        if f in all_scanners:
                            if not f in report["scans"].keys():
                                x_label.append(-1)
                            else:
                                label = 1.0 if report["scans"][f]["detected"] == True else 0.0
                                x_label.append(label)
                        elif f in all_permissions:
                            if "additional_info" in report.keys():
                                if "androguard" in report["additional_info"].keys():
                                    if "Permissions" in report["additional_info"]["androguard"].keys():
                                        label = 1.0 if f in report["additional_info"]["androguard"]["Permissions"].keys() else 0.0
                                        x_label.append(label)

                        elif f in all_tags:
                            label = 1.0 if f in report["tags"] else 0.0
                            x_label.append(label)

                        elif f.lower().find("age") != -1:
                            first_seen = datetime.strptime(report["first_seen"], "%Y-%m-%d %H:%M:%S")
                            today = datetime.fromtimestamp(time.time())
                            age = (today - first_seen).days / 360.0
                            x_label.append(age)

                        elif f.lower().find("submitted") != -1:
                            x_label.append(report["times_submitted"])
                        elif f.lower().find("positives") != -1:
                            x_label.append(report["positives"])
                        else: 
                            x_label.append(report["total"])

                    # Label app according to its VirusTotal report
                    if len(x_label) != labeler.n_features_:
                        prettyPrint("App \"%s\"'s dimensionality is different than classifier's. Skipping" % app, "warning")
                        continue

                    p = labeler.predict(x_label)[0]
                    X.append(x)
                    y.append(p)
                    # Label app using threshold-based schemes
                    # vt >= 1
                    label = 1.0 if report["positives"] >= 1 else 0.0
                    y_vt1.append(label)
                    # vt >= 4
                    label = 1.0 if report["positives"] >= 4 else 0.0
                    y_vt4.append(label)
                    # vt >= 10
                    label = 1.0 if report["positives"] >= 10 else 0.0
                    y_vt10.append(label)
                    # vt >= 50%
                    label = 1.0 if report["positives"]/float(report["total"]) >= 0.5 else 0.0
                    y_vt50p.append(label)
                    # vt >=50% + vt == 0
                    if report["positives"]/float(report["total"]) >= 0.5:
                        X_vt50p1.append(x)
                        y_vt50p1.append(1.0)
                    else:
                        if report["positives"] == 0:
                            X_vt50p1.append(x)
                            y_vt50p1.append(0.0)
                    # drebin
                    counter = 0
                    for scanner in drebin_scanners:
                        if scanner in report["scans"].keys():
                            label = 1.0 if report["scans"][scanner]["detected"] == True else 0.0
                            counter += label 
                    label = 1.0 if counter >= 2.0 else 0.0
                    y_drebin.append(label)
            
            # Load test app's ground truth
            if VERBOSE == "ON":
                prettyPrint("Loading test apps' feature vectors and ground truth")

            raw_truth = open(arguments.testgroundtruth).read().split('\n')
            lookup = {}
            for raw in raw_truth:
                if len(raw) > 0:
                    line = raw.split(',')
                    lookup[line[0]] = line[3] # SHA256,Package Name,DEX Date,My Label,Justification,VirusTotal Positives
 
            Xtest, ytest = [], []
            for app in testApps:
                key = app[app.rfind("/")+1:].replace(".%s" % arguments.fileext, "")
                x = eval(open(app).read())
                Xtest.append(x)
                ytest.append(float(lookup[key]))
           
            # Train a classifier
            prettyPrint("Training a %s classifier with different labeling schemes" % arguments.trainingclassifier)
            if arguments.trainingclassifier.find("KNN") != -1:
                neighbors = int(arguments.trainingclassifier.split('-')[-1])
                clf = KNeighborsClassifier(n_neighbors=neighbors)
            elif arguments.trainingclassifier.find("FOREST") != -1:
                estimators = int(arguments.trainingclassifier.split('-')[-1])
                clf = RandomForestClassifier(n_estimators=estimators, random_state=0)
            elif arguments.trainingclassifier.find("TREE") != -1:
                clf = DecisionTreeClassifier(random_state=0)
            elif arguments.trainingclassifier.find("SVM") != -1:
                clf = SVC(random_state=0, gamma='auto')
            elif arguments.trainingclassifier.find("DREBIN") != -1:
                clf = LinearSVC(random_state=0) 
            else:
                clf = GaussianNB()
            
            if VERBOSE == "ON":
                prettyPrint("Fitting model")
                
            clf.fit(X, y) # Fit using the labels from the loaded labeler
            p = clf.predict(Xtest)
            #print testApps
            #print ytest
            #print p
            metrics = calculateMetrics(ytest, p)
            prettyPrint("Using the loaded labeler \"%s\": MCC = %s, Recall = %s, Specificity = %s" % (arguments.savedlabeler, metrics["mcc"], metrics["recall"], metrics["specificity"]), "output")

            clf.fit(X, y_vt1) # vt >= 1
            p = clf.predict(Xtest)
            metrics = calculateMetrics(ytest, p)
            prettyPrint("Using vt >= 1: MCC = %s, Recall = %s, Specificity = %s" % (metrics["mcc"], metrics["recall"], metrics["specificity"]), "output")

            clf.fit(X, y_vt4) # vt >= 4
            p = clf.predict(Xtest)
            metrics = calculateMetrics(ytest, p)
            prettyPrint("Using vt >= 4: MCC = %s, Recall = %s, Specificity = %s" % (metrics["mcc"], metrics["recall"], metrics["specificity"]), "output")

            clf.fit(X, y_vt10) # vt >= 10
            p = clf.predict(Xtest)
            metrics = calculateMetrics(ytest, p)
            prettyPrint("Using vt >= 10: MCC = %s, Recall = %s, Specificity = %s" % (metrics["mcc"], metrics["recall"], metrics["specificity"]), "output")

            clf.fit(X, y_vt50p) # vt >= 50%
            p = clf.predict(Xtest)
            metrics = calculateMetrics(ytest, p)
            prettyPrint("Using vt >= 0.5: MCC = %s, Recall = %s, Specificity = %s" % (metrics["mcc"], metrics["recall"], metrics["specificity"]), "output")

            clf.fit(X_vt50p1, y_vt50p1) # vt == 0 && vt >= 50%
            p = clf.predict(Xtest)
            metrics = calculateMetrics(ytest, p)
            prettyPrint("Using vt == 0  && vt >= 0.5: MCC = %s, Recall = %s, Specificity = %s" % (metrics["mcc"], metrics["recall"], metrics["specificity"]), "output")

            clf.fit(X, y_drebin) # drebin
            p = clf.predict(Xtest)
            metrics = calculateMetrics(ytest, p)
            prettyPrint("Using drebin: MCC = %s, Recall = %s, Specificity = %s" % (metrics["mcc"], metrics["recall"], metrics["specificity"]), "output")
            

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Salam ya me3allem!")
    return True

if __name__ == "__main__":
    main()
