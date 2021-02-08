import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from matplotlib import pyplot
import time
start = time.time()

# load data
data = pd.read_csv("data.csv")
data = data.sample(frac=1).reset_index(drop=True)
data = data.drop(['task', 'CreationTimestamp', 'ProcessID', 'ParentPID', 'CommandLine', 'Image'] , axis = 1)
cols = data.columns.values.tolist()

# chia feature với lable
y = data['label']
X = data.drop(['label'], axis = 1)

# chia data train-test
X_train, X_test, y_train, y_test = train_test_split(X, y,test_size=0.2)

# train
model = RandomForestClassifier(n_estimators=10)
model.fit(X_train,y_train)
y_pred = model.predict(X_test)

print(classification_report(y_test,y_pred))
print(accuracy_score(y_test, y_pred))
print(time.time() - start)

importance = model.feature_importances_

for i,v in enumerate(importance):
	print('Feature: %s, Score: %.5f' % (cols[i],v))

pyplot.bar([x for x in range(len(importance))], importance)
pyplot.show()

