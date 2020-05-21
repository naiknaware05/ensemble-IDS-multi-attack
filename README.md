# Ensemble-IDS-multi-attack
This is our final year engineering project titled "Ensemble Based Intrusion Detection System". In this project we have tried to detect multi attacks using ensemble approaches of Machine Learning.

In multi attack environment, there would be more than one attack occurring simultaneously or within a short span of time. In our project, we have considered all those attacks as multi attacks which occur within one second of time span. We have proposed a system that captures live packets from the network and classifies whether the packet is normal or belongs to one of the subclasses of attack using various ensemble approaches such as Bagging, Boosting and Stacking. The highest accuracy we got is using XGBoost of 72.27%.

NSL-KDD dataset has been used for both training and testing the model. KDDExtractor from [here] (https://github.com/AI-IDS/kdd99_feature_extractor).
