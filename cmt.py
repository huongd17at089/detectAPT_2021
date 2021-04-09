
# def handel_label(data):
#     label_data = {}
#     for inc in data:
#         oid = inc["ProcessOID"]
#         if not oid in label_data:
#             label_data.update({inc["ProcessOID"]: int(0)})
#         new_val = max(label_data[oid], int(inc["ThreatLevel"]) + 1)
#         label_data.update({oid: new_val})
#     return label_data

# def handel_http_request(data):
#     http_request_data = {}
#     for http_req in data:
#         oid = http_req["ProcessOID"]
#         if not oid in http_request_data:
#             http_request_features = {"unknown_http_request": 0, "Suspicious_http_request": 0, "Malicious_http_request": 0, "unsafe_http_request": 0}
#             http_request_data.update({http_req["ProcessOID"]: http_request_features})
#         feature_name = levels[http_req["Type"]] + "_http_request"
#         new_val = int(http_request_data[oid].get(feature_name) or 0) + 1
#         http_request_data[oid].update({feature_name: new_val})
#     return http_request_data

# def handle_ip(processes, data):
#     ip_data = {}
#     for ip in data:
#         oid = ip["ProcessOID"]
#         if not oid in ip_data:
#             ip_features = {"unknown_ip": 0, "Suspicious_ip": 0, "Malicious_ip": 0, "unsafe_ip": 0}
#             ip_data.update({ip["ProcessOID"]: ip_features})
#         ip_data[oid].update({"domain" : ip["Domain"]})
#         feature_name = levels[ip["Type"]]+ "_ip"
#         new_val = int(ip_data[oid].get(feature_name) or 0) + 1
#         ip_data[oid].update({feature_name :  new_val})
#     for p in ip_data:
#         if p in processes:
#             processes[p].update(ip_data.get(p))
#     return ip_data

# print(handel_single_task('0c8d54b4-1f6b-431d-b14d-304182e66428.json')["5b33c0443628a5337a081498"])

#  nhap
# list_process = list(handel_single_task('0c8d54b4-1f6b-431d-b14d-304182e66428.json').values())
# df = pd.DataFrame.from_dict(list_process)
# df = df.drop(['domains'], axis=1)
# ex = ["task", "CreationTimestamp", "label"]
# df = df.reindex(columns=(ex[:-1] + list([a for a in df.columns if not a in ex]) + [ex[-1] ]))
# df.to_csv("demo.csv", index= False)
# print(df.columns)
# print(list)