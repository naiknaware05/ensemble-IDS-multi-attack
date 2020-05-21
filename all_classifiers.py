def xgboostClassifier(Feature_train, y_train, Feature_test):
  model = XGBClassifier(max_depth=6, colsample_bytree=0.9, colsample_bynode=0.9, colsample_bylevel=0.9, learning_rate=0.15, 
                          min_child_weight = 1 , n_estimators=100, objective='multi:softprob')
  model.fit(Feature_train, y_train)
  y_pred = model.predict(Feature_test)
  return y_pred

def baggingClassifier_DT(Feature_train, y_train, Feature_test):
  bag_clf = BaggingClassifier(DecisionTreeClassifier(max_depth = 6, criterion='gini', max_features=15, random_state=17),
                            n_estimators = 150, 
                            bootstrap=True, oob_score=True)
  bag_clf.fit(Feature_train, y_train)
  y_pred = bag_clf.predict(Feature_test)
  return y_pred

def adaboostClassifier(Feature_train, y_train, Feature_test):
  ada_clf = AdaBoostClassifier(DecisionTreeClassifier(max_depth=6,criterion='gini', max_features=17, random_state=17),
                             algorithm="SAMME.R",n_estimators=100, learning_rate= 1.5)
  ada_clf.fit(Feature_train, y_train)
  y_pred_ada = ada_clf.predict(Feature_test)
  return y_pred

def randomForestCLassifier(Feature_train, y_train, Feature_test):
  clf = RandomForestClassifier(n_estimators=1000)
  clf = clf.fit(Feature_train, y_train)
  y_pred = clf.predict(Feature_test)
  return y_pred

def extraTreesClassifier(Feature_train, y_train, Feature_test):
  clf = ExtraTreesClassifier(n_estimators=1000)
  clf = clf.fit(Feature_train, y_train)
  y_pred = clf.predict(Feature_test)
  return y_pred

def stackingClassifier(Feature_train, y_train, Feature_test):
  layer_one_estimators = [('rf_1', DecisionTreeClassifier(max_depth=6, max_features=15)), ('knn_1', KNeighborsClassifier(n_neighbors=35))]
  
  layer_two_estimators = [('dt_2', DecisionTreeClassifier(max_depth=6, max_features=15)),('rf_2', svm.SVC())]
  
  layer_two = StackingClassifier(estimators=layer_two_estimators, final_estimator=LogisticRegression())
  
  clf = StackingClassifier(estimators=layer_one_estimators, final_estimator=layer_two)
  clf = clf.fit(Feature_train, y_train)
  y_pred = clf.predict(Feature_test)
  return y_pred


#Importing Libraries
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score
from xgboost import XGBClassifier
from sklearn.ensemble import BaggingClassifier, AdaBoostClassifier, ExtraTreesClassifier, RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn import svm
from sklearn.ensemble import StackingClassifier

#Read datasets X1 for Training dataset and y1 for testing dataset
X1 = pd.read_csv("/content/drive/My Drive/KDDTrain+.csv")
y1 = pd.read_csv("/content/drive/My Drive/KDDTest+.csv")

print("Any null values in dataset : ", X1.isnull().values.any())

#Drop tuples with null values 
# X1 and y1 contains all 42 columns
X1.dropna(how='any',axis=0,inplace = True)
y1.dropna(how='any',axis=0,inplace = True)

# Select only those 28 columns which KDD_Extractor extracts from network packet
# These columns are for XGBOOST, Bagging and Adaboost (XBA)
KDD_Extractor_features_28 = ['duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes', 'land', 
                             'wrong_fragment', 'urgent', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 
                             'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
                             'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                             'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                             'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate','class']

# Select only those 26 columns which KDD_Extractor extracts from network packet
# These columns are for Random Forest, Extra Tree, Stacking (RES) 
KDD_Extractor_features_26 = ['duration', 'src_bytes', 'dst_bytes', 'land', 
                             'wrong_fragment', 'urgent', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 
                             'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
                             'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                             'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                             'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate','class']

# Select only KDD_Extractor columns
# Use this for XGBoost, Bagging, Adaboost (XBA)
X = pd.DataFrame(data = X1, columns = KDD_Extractor_features_28)
y = pd.DataFrame(data = y1, columns = KDD_Extractor_features_28)

'''
# Uncomment this, if you are using any of the "RES" classifiers.
# Select only KDD_Extractor columns
# Use this for Random Forest, Extra Tree, Stacking (RES)
X = pd.DataFrame(data = X1, columns = KDD_Extractor_features_26)
y = pd.DataFrame(data = y1, columns = KDD_Extractor_features_26)
'''

# Split the dataset into features and labels
X_train = X.iloc[:,:-1]
y_train = X.iloc[:,-1]
X_test = y.iloc[:,:-1]
y_test = y.iloc[:,-1]

print("X_train Shape : ",X_train.shape)
print("X_test Shape : ",X_test.shape)

'''
Encode the categorical values to numerical values.
And then drop the original attribute column containing categorical values.

For Random Forest, Extra Tree, Stacking (RES), no need of this encoding,
beacuse categorical columns doesn't exist in dataset and should be commented.
'''


#For training data
Feature_train = X_train
Feature_train = pd.concat([Feature_train,pd.get_dummies(X_train['protocol_type'])], axis=1)
Feature_train = Feature_train.drop(['protocol_type'], axis = 1)

Feature_train = pd.concat([Feature_train,pd.get_dummies(X_train['flag'])], axis=1)
Feature_train = Feature_train.drop(['flag'], axis = 1)


#For testing data
Feature_test = X_test
Feature_test = pd.concat([Feature_test,pd.get_dummies(X_test['protocol_type'])], axis=1)
Feature_test = Feature_test.drop(['protocol_type'], axis = 1)

Feature_test = pd.concat([Feature_test,pd.get_dummies(X_test['flag'])], axis=1)
Feature_test = Feature_test.drop(['flag'], axis = 1)

print("Feature_train Shape : ",Feature_train.shape)

print("Feature_test Shape : ",Feature_test.shape)

# Uncomment the classifier to be used

# Gives Accuracy: 72.27077%
y_pred = xgboostClassifier(Feature_train, y_train, Feature_test)

# Gives Accuracy: 71.84492%
#y_pred = baggingClassifier_DT(Feature_train, y_train, Feature_test)

# Gives Accuracy: 71.84492%
#y_pred = adaboostClassifier(Feature_train, y_train, Feature_test)

#y_pred = randomForestCLassifier(X_train, y_train, X_test)

#y_pred = extraTreesClassifier(X_train, y_train, X_test)

# Gives Accuracy: 71.41907%
#y_pred = stackingClassifier(X_train, y_train, X_test)

accuracy = accuracy_score(y_test, y_pred)
print("Accuracy: %.5f%%" % (accuracy * 100.0))
