#!/usr/bin/python

from Maat.utils.data import *
from Maat.utils.graphics import *
from Maat.utils.misc import *

import numpy as np
from sklearn.manifold import TSNE
from sklearn.decomposition import PCA
from scipy.cluster.hierarchy import dendrogram

from matplotlib import pyplot as plt
from matplotlib import rcParams, rc
import matplotlib.font_manager as font_manager
import plotly.plotly as py
from plotly.offline import plot, iplot
from plotly.graph_objs import *


RGB = ["#ff4136", "#3d9970", "#ff851b", "#6baed6", "#808389", "#48494c"] # Normal colors


def plotDendrogram(model):
    """
    Authors: Mathew Kallada
    License: BSD 3 clause
    =========================================
    Plot Hierarachical Clustering Dendrogram 
    =========================================
    This example plots the corresponding dendrogram of a hierarchical clustering
    using AgglomerativeClustering and the dendrogram method available in scipy.
    """
    try:
        # Children of hierarchical clustering
        children = model.children_
        # Distances between each pair of children
        # Since we don't have this information, we can use a uniform one for plotting
        distance = np.arange(children.shape[0])
        # The number of observations contained in each cluster level
        no_of_observations = np.arange(2, children.shape[0]+2)
        # Create linkage matrix and then plot the dendrogram
        linkage_matrix = np.column_stack([children, distance, no_of_observations]).astype(float)
        # Plot the corresponding dendrogram
        plt.title('Hierarchical Clustering Dendrogram')
        dendrogram(linkage_matrix)
        #plot_dendrogram(model, labels=model.labels_)
        plt.show()

    except Exception as e:
        prettyPrintError(e)
        return False

    return True

def reduceAndVisualizeMultiple(vectorsDirs, classNames, classMarkers, classColors, classOpacity, targetDim=2, reductionAlgorithm="tsne", fileExt="static", figSize=(1024,1024), figTitle="Data visualization", latexStyle=True, saveFig=True):
    """
    Generates a scatter plot after projecting the data points tSNE or PCA
    :param vectorsDirs: The directories containing the feature vectors to visualize or the feature vectors themselves
    :type vectorsDirs: list
    :param classNames: The names of classes for each directory of feature vectors (used in legend)
    :type classNames: list of str
    :param classMarkers: The markers to assign to the visualized vectors in each directory
    :type classMarkers: list of str
    :param classColors: The colors to assign to the visualized vectors in each directory
    :type classColors: list of str
    :param classOpacity: The opacity of data points in each class (for customized illustrations)
    :type classOpacity: list of float
    :param targetDim: The target dimensionality to project the feature vectors to (default=2)
    :type targetDiim: int
    :param reductionAlgorithm: The algorithm to use for dimensionality reduction
    :type reductionAlgorithm: str
    :param fileExt: The extension of files containing the feature vectors to visualize (default: .static)
    :type fileExt: str
    :param figSize: The size of the figure
    :type figSize: tuple (of ints)
    :param figTitle: The title of the figure and the name of the resulting HTML file
    :type figTitle: str
    :param latexStyle: Whether to use the fonts of LaTeX (default: True)
    :type latexStyle: boolean
    :param saveFig: Whether to save the generated scatter plot (default: True)
    :type saveFig: boolean
    :return: A boolean depicting the success/failure of the operaiton
    """
    try:
       # Sanity checks
       if not (len(vectorsDirs) == len(classNames) == len(classMarkers) == len(classColors) == len(classOpacity)):
           prettyPrint("The dimensionality of directories, names, markers, and colors does not match", "warning")
           return False

       # Check whether list of dirs or the feature vectors themselves
       if type(vectorsDirs[0]) == "str":
           # Loading the feature vectors
           X, y = [], []
           prettyPrint("Loading feature vectors")
           for d in vectorsDirs:
               for vector in glob.glob("%s/*.%s" % (d, fileExt)):
                   x = eval(open(vector).read())
                   X.append(x)
                   y.append(vectorsDirs.index(d))
       else:
           # Processing the feature vectors
           X, y = [], []
           for c in vectorsDirs:
               for x in c:
                   X.append(x)
                   y.append(vectorsDirs.index(c))


       prettyPrint("Successfully loaded %s vectors" % len(X))
       # Reduce dimensionality
       prettyPrint("Reducing the dimensionality of loaded vectors")
       reductionModel = TSNE(n_components=targetDim, random_state=0) if reductionAlgorithm == "tsne" else PCA(n_components=targetDim)
       # Apply transformation
       X_new = reductionModel.fit_transform(X)

       # Build and save figure
       if targetDim == 3:
            prettyPrint("Only 2-dimensional plots are currently supported for \"matplotlib\"", "warning")
            return False
       else:
           if latexStyle:
               font = {'family':'sans-serif', 'sans-serif':['Helvetica']}
               rc('font', **font)
               rc('text', usetex=True)
               plt.xlabel("$x_1$", **{"fontname": "Helvetica"})
               plt.ylabel("$x_2$", **{"fontname": "Helvetica"})

           else:
               plt.xlabel("x1")
               plt.ylabel("x2")

           plt.grid(zorder=0, linestyle="--") # Make dashed grid lines and send to background

           # And away we go
           prettyPrint("Building scatter plot")
           for c in classNames:
               classX1, classX2, className = [], [], c
               for index in range(len(X_new)):
                   if y[index] == classNames.index(c):
                       classX1.append(float(X_new[index][0]))
                       classX2.append(float(X_new[index][1]))

               label = "\\texttt{%s}" if latexStyle else "%s" 
               plt.scatter(classX1, classX2, c=classColors[classNames.index(c)], alpha=classOpacity[classNames.index(c)], marker=classMarkers[classNames.index(c)], label=label % className, linewidths=0.5, edgecolors="#000000", zorder=3)

           #plt.tick_params(
           #     axis='x',          # changes apply to the x-axis
           #     which='both',      # both major and minor ticks are affected
           #     bottom=True,       # ticks along the bottom edge are on
           #     top=False,         # ticks along the top edge are off
           #     labelbottom=False)
           #plt.tick_params(
           #     axis='y',          # changes apply to the y-axis
           #     which='both',      # both major and minor ticks are affected
                #left=True,         # ticks along the left edge are on
                #top=False,         # ticks along the top edge are off
           plt.legend(loc='best')
           #plt.show()

           plt.savefig('Visualization_%s.pdf' % figTitle.replace(" ", "_").lower())
           plt.savefig('Visualization_%s.pgf' % figTitle.replace(" ", "_").lower())


    except Exception as e:
        prettyPrintError(e)
        return False

    return True

