# Maat 

| Maat is a framework that mines VirusTotal scan reports to extract various information about the correctness, completeness, and consistency of scanners. It can also be used to train threshold-based and ML-based labeling strategies to label (Android) apps according to their VirusTotal scan reports that rival conventional, unsustainable threshold-based labeling strategies that are widely adopted by researchers. Maat also refers to the ancient Egyptian concepts of truth, balance, order, and harmony. | ![Maat](https://github.com/tum-i22/Maat/blob/master/icons/maat.png "Maat") |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------:|

## Dependencies
The current implementation depends on the following tools:
* [androguard](https://github.com/androguard/androguard): Used by Maat to statically analyze Android apps primarily to extract features from them.
* [scikit-learn](https://scikit-learn.org/stable/): Maat heavily relies on scikit-learn to select the best features extracted from VirusTotal scan reports, learn ML-based labeling strategies, and train/validate ML-based detection methods whose feature vectors are labeled using such ML-based labeled strategies.
* [Levenshtein](https://pypi.org/project/python-Levenshtein/): Python extension for computing string edit distances and similarities.
* [numpy](https://numpy.org/): Used alongside scikit-learn during learning tasks and calculating performances of different ML-based algorithms or calculating medians, means, and standard deviations of data we gather from the VirusTotal scan reports.
* [scipy](https://scipy.org/): Used to visualize hierarchical clustering dendograms.
* [matplotlib](https://matplotlib.org/): Used to visualize the results (e.g., most correct VirusTotal scanners), and trained trees in ML-based labeling strategies. 
* [plotly](https://plot.ly/python/): Used to generate more interactive plots.
* Any other libraries imported by Maat utils (e.g., data.py), are __currently not used by Maat__ and can be commented out. Those include *networkx*, *skimage*, *imutils*, *cv2*, and *alignment*.

## Maat's ML-based Labeling Strategies

![Maat's Process](https://github.com/tum-i22/Maat/blob/master/figures/Maat_Process.png "Maat's Process")

Maat, mines VirusTotal scan reports to build ML-based labeling strategies. As seen in figure above, Maat starts by
analyzing the VirusTotal scan reports of apps in the training dataset that were reanalyzed and downloaded at different points in time (i.e., t<sub>0</sub> , t<sub>1</sub> ,..., t<sub>m</sub>). In phase (1) we designate the VirusTotal scanners that achieve an average overall correctness rate of at least 0.90 between (**t<sub>0</sub>**) and September (**t<sub>m</sub>**) as the most correct scanners. Maat also finds the scanners that changed their verdicts at most 10% of the time (i.e., were stable 90% of the time), are considered. The output of this phase is an intersection of the most correct and stable VirusTotal scanners.

In phase (2), we extract features from the VirusTotal scan reports of apps in the training dataset. There are two types of features we extract from the reports, namely engineered features and naive features. Engineered features attempt to leverage the insights we gained from the previous sections (e.g., which scanners are correct). So, based on the output from phase (1), we consider the verdicts given to apps in the training dataset only by the set of most correct and stable scanners. To accommodate the impact of time on the maturity of an app’s scan report, we also include the age of a scan report in years, the number of times an app has been submitted for (re)analysis (i.e., times_submitted), the positives attribute, and the total attribute in this feature set. Lastly, to capture any patterns that Android (malicious) apps share in terms of functionalities and runtime behaviors, we extract from the VirusTotal scan reports the permissions that apps request in their ```AndroidManifest.xml``` files, and the tags given to them by VirusTotal (e.g., *checks-gps*, *contains-elf*, *sends-sms*, etc.). 

Naive features do not consider the outputs of phase (1). With naive features, we consider the verdicts given by **all** VirusTotal scanners to the apps in the training dataset. So, the feature vector extracted from a VirusTotal scan report will be a sequence of integers depicting the label given by each scanner to an app (i.e., -1 for not scanned, 0 for scanned and deemed benign, and 1 for scanned and deemed malicious). For example, assume that the scan report of an arbitrary app (![equation](http://www.sciweavers.org/tex2img.php?eq=\alpha&bc=White&fc=Black&im=jpg&fs=12&ff=arev&edit=)) contained scan results of three scanners, that respectively deemed (![equation](http://www.sciweavers.org/tex2img.php?eq=\alpha&bc=White&fc=Black&im=jpg&fs=12&ff=arev&edit=)) as malicious, malicious, and benign, the feature vector depicting this scan report will be (x<sub>![equation](http://www.sciweavers.org/tex2img.php?eq=\alpha&bc=White&fc=Black&im=jpg&fs=12&ff=arev&edit=)</sub> = (1, 1, 0)). With naive features, we allow ML-based labeling strategies to utilize the verdicts of all VirusTotal freely scanners regardless of their correctness or stability.

Phase (3) is an optional phase that selects the most informative features extracted from the training dataset's scan
reports. To avoid having to choose the number of features to select arbitrarily, we utilize the [SelectFromModel](https://scikit-learn.org/stable/modules/generated/sklearn.feature_selection.SelectFromModel.html) technique to select the most informative features automatically. In essence, this technique selects features based on the importance given to them by a model (e.g., logistic regression, support vector machines, decision trees, etc.). For example, during training, decision trees iteratively utilize a criterion (e.g., Gini index), to decide upon the next feature to consider in splitting data points into two, or more, classes; in our case, this feature could be a scanner's verdict regarding the label of an app. Ultimately, the trained tree will compile a set of features that it used during splitting and assign an importance value to each one of them. The SelectFromModel feature selection technique uses such importance values and returns the user those features with importance values more than a preset threshold (i.e., 1x10<sup>-5</sup> in the case of decision trees). For our experiments, we rely on decision trees as the model used by the SelectFromModel technique to extract the most informative features.

We envision the process of utilizing the features extracted from VirusTotal scan reports to label apps as a series or combination of questions, such as how many scanners deem the app malicious? how old is the app? does a renowned scanner (e.g., AVG) deem the app as malicious? The machine learning classifier that mimics this model, we reckon, is a decision tree. In order not to rely on the decisions made by a single tree, Maat trains ML-based labeling strategy as a collection of trees or a random forest. To estimate the hyperparameters (e.g., the maximum depth each tree is allowed to grow), that train the most effective forests, we use the techniques of [grid search](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.GridSearchCV.html) and [random(ized) search](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.RandomizedSearchCV.html) to select from among a set of parameters below. In our experiments, we compare the performance of random forests trained using both search techniques.

The output of phase (4) is a random forest that takes a vector of numerical features extracted from an app's VirusTotal scan report and returns a label depicting the class of the app (i.e., 1.0 for malicious and 0.0 for benign). Effectively, this random forest is a labeling strategy. In phase (5), given the VirusTotal scan report of an arbitrary Android app, the report is represented as a feature vector that matches the features used by the random forest (e.g., naive versus engineered features), and is used to predict the app's class.

### [Maat's Engineered Features](#EngineeredFeatures)

The following list enumerates the engineered features extracted from the ```VirusTotal``` scan reports of apps in our training dataset. The order of features in the list mimics the order of every feature in the feature vector.

* The verdicts (i.e., 1 for malicious, 0 for benign, and -1 for unknown), given by the most correct ```VirusTotal``` scanners as of September 27th, 2019. See **User Manual** for information about how to retrieve the "most correct" scanners:  
  * ```Avira```
  * ```CAT-QuickHeal```
  * ```DrWeb```
  * ```ESET-NOD32```
  * ```Fortinet```
  * ```Ikarus```
  * ```MAX``` (TrendMicro Maximum Security)
  * ```McAfee```
  * ```NANO-Antivirus```
  * ```Sophos```
  * ```SymantecMobileInsight```
* The age of a scan report in years calculated as the difference between today's date and that of __first_seen__'s
* The number of times the app was submitted to ```VirusTotal``` according to the __times_submitted___ field.
* The number of scanners deeming the app as malicious according to the __positives__ field.
* The total number of scanners that scanned the app according to the __total__ field.
* The list of permissions requested by the app out of 324 permissions. If a permissions is requested by an app, its corresponding index in the feature vector has a value of 1, and a value of 0 otherwise.
* The list of tags given by ```VirusTotal``` to the app out of 32 tags. If a tag is given to an app, its corresponding index in the feature vector has a value of 1, and a value of 0 otherwise. Examples of tags: ```contains-elf```, ```contains-pe```, ```xor```, and so on.

### [Maat's Selected Naive Features](#NaiveFeatures)

The following list enumerates the selected naive features, viz. the verdicts of ```VirusTotal``` scanners that train the best performing ML-based labeling strategies. The order of features in the list mimics the order of every feature in the feature vector.

* ```AhnLab-V3```
* ```Avira```
* ```CAT-QuickHeal```
* ```Cyren```
* ```DrWeb```
* ```ESET-NOD32```
* ```F-Secure```
* ```Fortinet```
* ```Ikarus```
* ```K7GW```
* ```MAX```
* ```McAfee```
* ```McAfee-GW-Edition```
* ```NANO-Antivirus```
* ```Sophos```
* ```SymantecMobileInsight```
* ```Trustlook```

### [Maat's Hyperparameter Estimation](#HyperparameterEstimation)

To train the best-performing random forests that constitute the ML-based labeling strategies, Maat uses the techniques of grid search and random(ized) search to estimate the hyperparameters of the decision trees in those forests. We used 10-Fold Cross Validation to train random forests of 100 decision trees and varied the following parameters as follows:

* The criterion used to choose the feature to test to futher split the training dataset into malicious and benign apps ```criterion```: {gini, entropy}.
* The maximum depth a decision tree is allowed to grow ```max_depth```: {1, 4, 10, None}.
* The maximum number of features a decision tree is allowed to check upon every split ```max_features```: {3, 5, 10, None}.
* The minimum number of samples required to split a node in a tree ```min_samples_split```: {2, 3, 10}.
* If False, the entire dataset is used to train the decision tree instead of bootstrap samples ```bootstrap```: {True, False}


## User Manual 

Maat is implemented as Python API that is meant to analyze and manipulate ```VirusTotal``` scan reports. The following calls exhibit how this API can be used to calculate some interesting results from a collection of scan reports. The format of a scan report is nothing but a string representation of the ```JSON``` report you can download from ```VirusTotal```'s API. We assume that the report such scan reports has a ```.report``` extension. Reports are loaded within the API using the call ```eval(open([path_to_report_file]).read())```.

### Calculate Scanners' Detection Rates

Currently this method is implemented to support apps in the [AMD](http://amd.arguslab.org/) dataset because it displays the detection rates grouped by the malware type, which is supported by AMD.

```
from Maat.mining import malignancy
malignancy.getAMDDetectionRates(vtReportsDir, generateLatexTable)
```

### Get Scanners' Correctness Rates

The ```groundTruth``` parameter depicts a dictionary with keys being the ```SHA256``` hash of each app and values being a binary label (i.e., 0.0 for benign and 1.0 for malicious). The parameter ```hashToTypeMapping``` is another dictionary with the same keys as the former dictionary and values of strings depicting the malware type as reported by AMD.

```
from Maat.mining import correctness
correctness.getCorrectnessByType(datasetDir, vtReportsDir, groundTruth, hashToTypeMapping) # Only hash to type, not to type and family
```

### Get Scanners' Correctness Rates (Over a period of time)

```
from Maat.mining import correctness
correctness.getCorrectnessOverTime(datasetDir, vtReportsDirs, groundTruth, generateLinePlot=True, plotScanners=["Avira", "McAfee", ...])
correctness.getMostCorrectScannersOverTime(datasetDir, vtReportsDirs, groundTruth, averageCorrectness=0.9, generateLinePlots=True, plotScanners=["Avira", "McAfee", ...])
```

### Experiment 1: Accurate Labeling 

The Maat API can be used to build tools to train ML-based labeling strategies to label Android apps according to their ```VirusTotal``` scan reports. We wrote a tool called ```maat_tool.py``` that supports three types of experiments. Running the command ```python maat_tool.py --help``` returns the following:

```
usage: Maat_tool.py [-h] -t {naive_experiments,advanced_experiments}
                    [-m MALICIOUSDIR] [-b BENIGNDIR] -d VTREPORTSDIRS
                    [VTREPORTSDIRS ...] [-y TRAININGDATASETDIR] -x
                    TESTDATASETDIR [-e FILEEXT] -v TESTVTREPORTSDIR -g
                    TESTGROUNDTRUTH [-f {naive,engineered,both}]
                    [-c {forest,bayes,knn}] [-n CLASSIFIERNAME]
                    [-s {GridSearch,RandomSearch}] [-o SAVEDLABELER]
                    [-l TRAININGCLASSIFIER]

Utilizes the Maat API to mine VirusTotal reports and return insights about
them.

optional arguments:
  -h, --help            show this help message and exit
  -t {naive_experiments,advanced_experiments}, --task {naive_experiments,advanced_experiments}
                        The task to accomplish after analyzing the VirusTotal
                        reports
  -m MALICIOUSDIR, --maliciousdir MALICIOUSDIR
                        The directory containing the malicious APKs
                        (naive_experiments)
  -b BENIGNDIR, --benigndir BENIGNDIR
                        The directory containing the benign APKs
                        (naive_experiments)
  -d VTREPORTSDIRS [VTREPORTSDIRS ...], --vtreportsdirs VTREPORTSDIRS [VTREPORTSDIRS ...]
                        The directories containing the VirusTotal reports
                        (both experiments)
  -y TRAININGDATASETDIR, --trainingdatasetdir TRAININGDATASETDIR
                        The directory containing the feature vectors to use to
                        train classifiers to assess a pre-trained labeler
                        (advanced_experiments)
  -x TESTDATASETDIR, --testdatasetdir TESTDATASETDIR
                        The directory containing the feature vectors of the
                        test APK's (both experiments)
  -e FILEEXT, --fileext FILEEXT
                        The extension of the feature vector files
  -v TESTVTREPORTSDIR, --testvtreportsdir TESTVTREPORTSDIR
                        The directory containing the VirusTotal reports of the
                        test apps (both experiments)
  -g TESTGROUNDTRUTH, --testgroundtruth TESTGROUNDTRUTH
                        The CSV file containing the ground truth of apps in
                        the test dataset (both experiments)
  -f {naive,engineered,both}, --featurestype {naive,engineered,both}
                        The type of features to extract from the training
                        dataset
  -c {forest,bayes,knn}, --labelingclassifier {forest,bayes,knn}
                        The classifier to use to label apps
                        (naive_experiments)
  -n CLASSIFIERNAME, --classifiername CLASSIFIERNAME
                        The name to give to the saved labeling classifier
                        (naive_experiments)
  -s {GridSearch,RandomSearch}, --searchstrategy {GridSearch,RandomSearch}
                        The strategy used to find the best estimator for tree-
                        based labeling (naive_experiments)
  -o SAVEDLABELER, --savedlabeler SAVEDLABELER
                        The labeler you wish to use to label apps in a dataset
                        (advanced experiments)
  -l TRAININGCLASSIFIER, --trainingclassifier TRAININGCLASSIFIER
                        The type of classifier to train using the training
                        feature vectors (advanced experiments). Examples:
                        KNN-5, DREBIN, FOREST-10, SVM, GNB, TREE
```

Here's an example on how to run experiment 1 to label apps:

```
python maat_tool.py --task naive_experiments --maliciousdir ../data/app_apk/AMD/ --benigndir ../data/app_apk/Gplay_AndroZoo --vtreportsdirs ../data/vt_reports_201* --testdatasetdir ../data/app_apk/sampled_AndroZoo/ --testvtreportsdir ../data/vt_reports_2019-07-05/ --testgroundtruth ../data/app_apk/sampled_AndroZoo/labels.csv --searchstrategy RandomSearch --labelingclassifier forest --classifiername sampled --featurestype naive
```

### Experiment 2: Enhancing Detection Methods

Using the same tool, one can use pre-trained ML-based labeling strategies to label apps used to train different classifiers, and test the ability of those classifiers to detect out-of-sample apps. Here's an example on how to do that:

```
python maat_tool.py --task advanced_experiments --trainingdatasetdir ../data/feature_vectors/androzoo_2019/static/ --vtreportsdirs ../data/vt_reports_201* --testdatasetdir ../data/feature_vectors/sampled_AndroZoo/static/ --testvtreportsdir ../data/vt_reports_2019-07-05/ --testgroundtruth ../data/app_apk/sampled_AndroZoo/labels.csv --fileext static --savedlabeler sampled_forest_gridsearch_naive_full.txt --trainingclassifier FOREST-25
```
### [Static Features](#StaticFeatures)

The following list enumerates the numerical features statically extracted from the APK archives of Android apps with the help of androguard's python API. These features (total 40) are primarily used to train ML-based detection methods. Features are grouped by their types (i.e., basic features, permission-based features, API call features, etc.). The order of features in the list mimics the order of every feature in the feature vector. 

* Basic features:
  * Minimum SDK version supported by the app.
  * Maximum SDK version supported by the app.
  * Total number of activities in the app.
  * Total number of services in the app.
  * Total number of broadcast receivers in the app.
  * Total number of content providers in the app.
* Permission-based features:
  * Total number of requested permissions.
  * Ratio of Android permissions to total permissions.
  * Ratio of custom permissions to total permissions.
  * Ratio of dangerous permissions to total permissions.
* API call features:
  * Total number of classes in ```classes.dex```. 
  * Total number of methods in ```classes.dex```.
  * Counts of calls to methods in the following packages:
    * ```android.accounts.AccountManager```
    * ```android.app.Activity```
    * ```android.app.DownloadManager```
    * ```android.app.IntentService```
    * ```android.content.ContentResolver```
    * ```android.contentContextWrapper```
    * ```android.content.pm.PackageInstaller```
    * ```android.database.sqlite.SQLiteDatabase```
    * ```android.hardware.Camera```
    * ```android.hardware.display.DisplayManager```
    * ```android.location.Location```
    * ```android.media.AudioRecord```
    * ```android.media.MediaRecorder```
    * ```android.net.Network```
    * ```android.net.NetworkInfo```
    * ```android.net.wifi.WifiInto```
    * ```android.net.wifi.WifiManager```
    * ```android.os.PowerManager```
    * ```android.os.Process```
    * ```android.telephony.SmsManager```
    * ```android.widget.Toast```
    * ```dalvik.system.DexClassLoader```
    * ```dalvik.system.PathClassLoader```
    * ```java.lang.class```
    * ```java.lang.reflect.Method```
    * ```java.net.HttpCookie```
    * ```java.net.URL.openConnection```
* Miscellaneous features:
  * Zero-based index of the compiler used to compile the app from the list of (```dx```, ```dexmerge```, ```dexlib 1.x```, ```dexlib 2.x```, ```Jack 4.x```, or unknown)

## Miscellaneous

### Malware Types

The malware types we consider in so far can be found in the Python module __Maat.shared.constants__ under the variable ```amd_types```. Feel free to add more types to the following list:

* **Adware**
* **Backdoor**
* **HackerTool**
* **Ransom**
* **Trojan**
* **Trojan-Banker**
* **Trojan-Clicker**
* **Trojan-Dropper**
* **Trojan-SMS**
* **Trojan-Spy**

### [Reverse Engineering Apps](#Reverse)

The following steps depicts the process we adopted to manually analyze and label apps in our test datasets. Given an app (![equation](http://www.sciweavers.org/tex2img.php?eq=\alpha&bc=White&fc=Black&im=jpg&fs=12&ff=arev&edit=)), we:
* Install (![equation](http://www.sciweavers.org/tex2img.php?eq=\alpha&bc=White&fc=Black&im=jpg&fs=12&ff=arev&edit=)) on a rooted Android Virtual Device (AVD) containing the [```Xposed```](http://api.xposed.info/reference/packages.html) framework and the API call monitoring tool [```droidmon```](https://github.com/idanr1986/droidmon).
* run and interact with (![equation](http://www.sciweavers.org/tex2img.php?eq=\alpha&bc=White&fc=Black&im=jpg&fs=12&ff=arev&edit=)) on the AVD and monitor the API calls it issues during runtime.
* If app crashes or no malicious behavior is noticed: decompile (![equation](http://www.sciweavers.org/tex2img.php?eq=\alpha&bc=White&fc=Black&im=jpg&fs=12&ff=arev&edit=)) with [```Jadx```](https://github.com/skylot/jadx) and inspect its source code.
* If no traces of malicious code are found, disassemble (![equation](http://www.sciweavers.org/tex2img.php?eq=\alpha&bc=White&fc=Black&im=jpg&fs=12&ff=arev&edit=)) with [```Apktool```](https://ibotpeaches.github.io/Apktool/) and reverse engineer its ```Smali``` code.
* If no traces of malicious code are found, disassemble the shared object libraries used by ($\alpha$) using [```Gidhra```](https://github.com/NationalSecurityAgency/ghidra) and inspect ```C/C++``` code.
* If no traces of malicious code are found, provisionally deem an app as benign and check ```VirusTotal``` regarding the app's status.
* If ```VirusTotal``` report gives a total of _zero_ positives, deem app as benign. Otherwise, inspect the scanners deeming app as malicious, the label they give to an app (e.g., **Riskware**), and the details inside the scan report.
* If the aforementioned details reveal malicious behavior, deem as such. Otherwise, deem app as benign.

### [Homegrown Dataset](#Homegrown)

The ```SHA1``` hashes, a short description, and the ```VirusTotal``` __positives__:__total__ fields of apps in the **Homegrown** dataset, as of October 11th, 2019.

| ```SHA1``` Hash | Description | ```Virustotal``` __positives__ | ```Virustotal``` __total__ |
| ------------- | ------------- | ------------- | ------------- |
| 17866baec8c1179264c585934d742a7befa20975 | Encryption-based Ransomware demo app | 0 | 58 |
| 1b8235f2ad665df5f8632b75a1b466f849654934 | Tapjacking-based tracking app and WiFi password stealer | 0 | 59 |
| 1c7c935ba48c5db86ff4fd957fedc3e691484c77 | Tapjacking and overlay-based Ransomware demo app | 0 | 58 |
| 31cf1a7a7f8a3bb6f9fdb45267dcbf9ff449b994 | Repackaged app with encryption-based Ransomware payload | 0 | 37 |
| 66c16d79db25dc9d602617dae0485fa5ae6e54b2 | Repackaged app with logic-based payload to delete user contacts | 1 | 58 |
| 691973efb45176862085e4d4e081dfa8750590f7 | Repackaged antiviral software with backdoor | 0 | 60 |
| aa0d0f82c0a84b8dfc4ecda89a83f171cf675a9a | Repackaged mail client with obfuscated encryption-based Ransomware | 0 | 60 |
| bee87f0ae97b438488cbe351311d5d40ccf8c3e0 | Launcher-based Ransomware demo app | 0 | 60 |

### [BitDefender and Panda on VirusTotal versus Reality](#AMDSample)

The ```SHA1``` hashes of ten apps randomly sampled from the [AMD](http://amd.arguslab.org/) dataset, the number of scanners deeming them as malicious as of October 10th, 2019, their malware types, and whether ```BitDefender```'s version 3.3.063 and ```Panda```'s version 3.4.5 managed to detect (:heavy_check_mark:) them.

| ```SHA1``` Hash | ```Virustotal``` __positives__ | Malware Type | ```BitDefender``` | ```Panda``` |
| ------------- | ------------- | ------------- | ------------- | ------------- |
| fdf0835597adc16d667b4cbaef0fc3ee76205503 | 20 | **Adware** |  |  |
| 3425e68789614cbda4284169589f7aeab8e28b28 | 28 | **Trojan-SMS** | :heavy_check_mark: | :heavy_check_mark: |
| 11c8678985aaa5ce4bcd5970a0008b0310c88a7e | 34 | **Trojan-SMS** | :heavy_check_mark: | :heavy_check_mark: |
| 7693726e8f286d6dd8c115c273637d44c554f19c | 26 | **Trojan-Banker** | :heavy_check_mark: |  |
| a0e7e36eec83339980f056a7af5f36d5dc99809e | 31 | **Ransom** | :heavy_check_mark: | :heavy_check_mark: |
| 74581e2e0c7b93391574ec8582d274432a4a2838 | 19 | **Adware** |   |  |
| a9a46d346a2ae5a397517c70d249695c6c89632b | 15 | **Adware** |   |  |
| db9603ffa852f1b0aad3f44418db44893db3f726 | 23 | **Adware** | :heavy_check_mark: |  |
| 7f9e6bc600b4a02b5d15a6511a43419d1aa500ff | 23 | **Adware** | :heavy_check_mark: |  |
| d4eb21ae5c2b4b05c0f3ce4e5117c56d9c3746ef | 18 | **Adware** | :heavy_check_mark: |  |

## Citation and Contact

For more information about the design and implementation of the tool, please refer to the paper cited below. Kindly consider citing our paper, if you find it useful in your research.

```
To be updated.
```

We are constantly updating the source code and its corresponding documentation. However, should you have any inquiries about installing and using the code, please contact us:

Alei Salem (salem@in.tum.de)
