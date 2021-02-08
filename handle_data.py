import pandas as pd

df = pd.read_csv("data.csv")
df["Scores_Network"] = df["Scores_Network"].astype(int)
df["Autostart"] = df["Autostart"].astype(int)
df["LowAccess"] = df["LowAccess"].astype(int)
df["ProcessType"] = df["ProcessType"].astype("category").cat.codes + 1
df["FileType"] = df["FileType"].astype("category").cat.codes + 1
df.to_csv("data.csv", index= False)
