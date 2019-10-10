#!/usr/bin/python

from Maat.utils.data import *
from Maat.utils.graphics import *
from Maat.utils.misc import *

import numpy as np
from sklearn.manifold import TSNE
from sklearn.decomposition import PCA
from scipy.cluster.hierarchy import dendrogram

from matplotlib import pyplot as plt
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

def reduceAndVisualize(X, y, dim=2, reductionAlgorithm="tsne", figSize=(1024,1024), figTitle="Data visualization", appNames=[], customLabels=("label1", "label2")):
    """
    Generates a scatter plot using "plotly" after projecting the data points into <dim>-dimensionality using tSNE or PCA
    :param X: The matrix containing the feature vectors
    :type X: list
    :param y: The labels of the feature vectors
    :type y: list
    :param dim: The target dimensionality to project the feature vectors to (default=2)
    :type dim: int
    :param reductionAlgorithm: The algorithm to use for dimensionality reduction
    :type reductionAlgorithm: str
    :param figSize: The size of the figure
    :type figSize: tuple (of ints)
    :param figTitle: The title of the figure and the name of the resulting HTML file
    :type figTitle: str
    :param appNames: The names of apps to be used as tooltips for each data point. Assumed to match one-to-one with the feature vectors in X
    :type appNames: list of str
    :param customLabels: The labels two use for the two visualized classes
    :type customLabels: tuple of str
    :return: A bool depicting the success/failure of the operaiton
    """
    try:
        # Prepare data
        X, y = np.array(X), np.array(y)
        # Build model
        reductionModel = TSNE(n_components=dim) if reductionAlgorithm == "tsne" else PCA(n_components=dim)
        # Apply transformation
        prettyPrint("Projecting %s feature vectors of dimensionality %s into %s-d" % (X.shape[0], X.shape[1], dim))
        X_new = reductionModel.fit_transform(X)
        # Generate a scatter plot
        prettyPrint("Populating the traces for malware and goodware")
        # Create traces for the scatter plot 
        prettyPrint("Creating a scatter plot")

        if dim == 3:
            prettyPrint("Only 2-dimensional plots are currently supported for \"matplotlib\"", "warning")
            return False
        else:
            x1_class1, x1_class2, x2_class1, x2_class2 = [], [], [], []
            for index in range(len(X)):
                if y[index] == 0:
                    x1_class1.append(X_new[index][0])
                    x2_class1.append(X_new[index][1])
                else:
                    x1_class2.append(X_new[index][0])
                    x2_class2.append(X_new[index][1])

            plt.scatter(x1_class1, x2_class1, c=getRandomHexColor(), alpha=0.5, marker=getRandomMarker(), label=customLabels[0])
            plt.scatter(x1_class2, x2_class2, c=getRandomHexColor(), alpha=0.5, marker=getRandomMarker(), label=customLabels[1])
            plt.xlabel("x1")
            plt.ylabel("x2")
            plt.tick_params(
                axis='x',          # changes apply to the x-axis
                which='both',      # both major and minor ticks are affected
                bottom=True,       # ticks along the bottom edge are on
                top=False,         # ticks along the top edge are off
                labelbottom=False)
            plt.tick_params(
                axis='y',          # changes apply to the y-axis
                which='both',      # both major and minor ticks are affected
                left=True,         # ticks along the left edge are on
                top=False,         # ticks along the top edge are off
                labelleft=False)
            plt.legend(loc='best')
            #plt.show()
    
            plt.savefig('Visualization_%s.pdf' % figTitle.replace(" ", "_").lower())
            plt.savefig('Visualization_%s.pgf' % figTitle.replace(" ", "_").lower())

    except Exception as e:
        prettyPrintError(e)
        return False

    return True



