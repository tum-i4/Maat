#!/usr/bin/python

from Maat.utils.graphics import *
from Maat.shared.constants import *
from Maat.conf.config import *

from numpy import mean, median, std

import glob, os

def getAMDDetectionRates(vtReportsDir, generateLatexTables=False):
    """
    Calculate the detection rate for each VirusTotal scanner on different malware types and families in the AMD dataset
    :param vtReportsDir: The directory containing the VirusTotal scan reports
    :type vtReportsDir: str
    :param generateLatexTable: Whether to generate two strings to directly use in LaTeX
    :type generateLatexTable: bool
    :return: Two dict's containing the detection rates per malware type and family and two str's of the generated LaTeX tables
    """
    try:
        latexTableType, latexTableFamily = "", ""
        # Load a look up dictionary with app keys, families, and types
        amdFamiliesAndTypes = eval(open("%s/amd_families_types.txt" % LOOKUP_STRUCTS).read())
       
        # Retrieve the AMD apps and iterate over them
        # Ready the structures to hold the detection rates
        detectionRatesFamily, detectionRatesType = {}, {}
        for family in amd_families:
            detectionRatesFamily[family] = []
        for typ in amd_types:
            detectionRatesType[typ] = []
        # And iterate
        for amdApp in amdFamiliesAndTypes:
            if VERBOSE == "ON":
                prettyPrint("Processing \"%s\", #%s out of %s" % (amdApp, amdFamiliesAndTypes.keys().index(amdApp), len(amdFamiliesAndTypes)), "debug")
            if os.path.exists("%s/%s.report" % (vtReportsDir, amdApp)):
                report = eval(open("%s/%s.report" % (vtReportsDir, amdApp)).read())
                detectionRatesFamily[amdFamiliesAndTypes[amdApp][0]].append(float(report["positives"])/report["total"])
                detectionRatesType[amdFamiliesAndTypes[amdApp][1]].append(float(report["positives"])/report["total"])

        # Print the results and build the LaTeX tables if needed
        prettyPrint("Here are your results", "output")
        for family in amd_families: # Just because it is sorted alphabetically
            if not family in detectionRatesFamily.keys():
                prettyPrint("Could not calculate rates for family \"%s\"" % family, "warning")
                continue
            
            data = detectionRatesFamily[family]
            prettyPrint("\"%s\": mean rate = %s, median rate = %s, std. deviation rate = %s" % (family, mean(data), median(data), std(data)), "output")
            if generateLatexTables:
                latexTableFamily += "%s & %s & %s & %s & %s \\\ \hline\n" % (family, len(data), round(mean(data), 2), round(median(data), 2), round(std(data), 2))

        # Do the same for type
        prettyPrint("-" * 100)
        for typ in amd_types: # Just because it is sorted alphabetically
            if not typ in detectionRatesType.keys():
                 prettyPrint("Could not calculate rates for type \"%s\"" % typ, "warning")
                 continue

            data = detectionRatesType[typ]
            prettyPrint("\"%s\": mean rate = %s, median rate = %s, std. deviation rate = %s" % (typ, mean(data), median(data), std(data)), "output")
            if generateLatexTables:
                latexTableType += "%s & %s & %s & %s & %s \\\ \hline\n" % (typ, len(data), round(mean(data), 2), round(median(data), 2), round(std(data), 2))


    except Exception as e:
        prettyPrintError(e)
        return {}, {}, "", ""

    return detectionRatesType, detectionRatesFamily, latexTableType, latexTableFamily

