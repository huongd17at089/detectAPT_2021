import pandas as pd
import json
from builtins import any
import glob
import os

# constant
features = ["ip", "domain", "http_request"]
levels = ["unknown", "Suspicious", "Malicious", "whitelist", "unsafe"]

registry_features = ["f_r1", "f_r2", "f_r3", "f_r4", "f_r5", "f_r6"]

# 7 nhóm security-sensitive registry keys
rk_security_sensitive = [
    "CurrentVersion\RunServices","CurrentVersion\RunServicesOnce","CurrentVersion\Run","CurrentVersion\RunOnce","CurrentVersion\RunOnceEx",
    "Microsoft\Active Setup",
    "CurrentControlSet\Services",
    "Windows\AppInit_DLLs","Session Manager\AppCertDLLs","Windows\LoadAppInit_DLLs",
    "exefile\shell\Open\command","comfile\shell\Open\command","batfile\shell\Open\command","htafile\Shell\Open\Command","piffile\shell\Open\command"
    "CurrentVersion\Internet Settings",
    "Explorer\Browser Helper Objects"
]

# path file nhay cam
drop_sensitive = [
    "Program Files", "Program Files (x86)"
    "Windows",
    "Temp",
    "Windows\Temporary Internet Files", "Microsoft\CryptnetUrlCache", "Roaming\Macromedia", "Default\Cookies"
]

def init(task_id,data):
    process = {}
    for p in data :
        key = p["OID"]
        p.pop("OID")
        p.update({"Priority" : 0,"task": task_id, "domains": [], "label" : 0 })
        for f in features:
            for l in levels:
                p.update({l + "_" + f: 0})
        for r in registry_features:
            p.update({r: 0})
        p.update(
            {"drop_all": 0, "totalDropFileSize": 0, "drop_sensitive": 0, "totalDropSensiSize": 0 })
        process.update({key: p})
    return process


# So luong ip cho feature dc dinh nghia
def handle_ip(processes, data):
    for ip in data:
        oid = ip["ProcessOID"]
        if oid in processes:
            domains = processes[oid]["domains"]
            domains.append(ip["Domain"])
            feature_name = levels[ip["Type"]]+ "_ip"
            new_val = int(processes[oid].get(feature_name) or 0) + 1
            processes[oid][feature_name] = new_val

def handel_domain(processes, data):
    domain_data = {}
    for d in data:
        domain = d["Domain"]
        if not domain in domain_data:
            domain_data.update({domain: 0})
        domain_data[domain] = max(domain_data[domain], d["Type"] +1)
    for p in processes:
        process = processes[p]
        domains = process["domains"]
        for d in domains:
            if(d in domain_data):
                feature_name = levels[domain_data[d]-1] + "_domain"
                new_val = int(process[feature_name] or 0) + 1
                process[feature_name] = new_val


def handel_http_request(processes,data):
    for http_req in data:
        oid = http_req["ProcessOID"]
        if oid in processes:
            feature_name = levels[http_req["Type"]] + "_http_request"
            new_val = int(processes[oid].get(feature_name) or 0) + 1
            processes[oid][feature_name] = new_val

# lay gia tri max cua label
def handel_label(processes, incidents):
    for inc in incidents:
        oid = inc["ProcessOID"]
        if (oid in processes):
            new_val = max(processes[oid]["label"], int(inc["ThreatLevel"]) + 1)
            processes[oid]["label"] = new_val

# lay gia tri max cua priority
def handel_priority(processes, threats):
    for thr in threats:
        oid = thr["ProcessOID"]
        if (oid in processes):
            new_val = max(processes[oid]["Priority"], int(thr["Priority"]) + 1)
            processes[oid]["Priority"] = new_val


# f_r1 Tổng số thao tác ghi thành công trên các giá trị đăng ký
# f_r2 Tổng số thao tác ghi không thành công trên các giá trị đăng ký

# f_r3 Tổng số thao tác ghi đường dẫn hệ thống Windows tới các giá trị đăng ký

# f_r4 Số hoạt động ghi thành công trên các giá trị đăng ký nhạy cảm với bảo mật
# f_r5 Số lần thao tác ghi không thành công trên các giá trị đăng ký nhạy cảm với bảo mật

# f_r6 Số hoạt động ghi đường dẫn hệ thống Windows đến các giá trị đăng ký nhạy cảm với bảo mật

def handel_registry(processes, data):
    # print(data[0])
    for r in data:
        oid = r["ProcessOID"]
        if( oid in processes):
            key = r["Key"]
            value = r["Value"]
            operation = r["Operation"]
            typeValue = r["TypeValue"]

            if(operation == "write"):
                if(value != ""):
                    processes[oid]["f_r1"] = int(processes[oid]["f_r1"] or 0) + 1
                    if(any(x in key for x in rk_security_sensitive)):
                        processes[oid]["f_r4"] = int(processes[oid]["f_r4"] or 0) + 1

                if(value == ""):
                    processes[oid]["f_r2"] = int(processes[oid]["f_r2"] or 0) + 1
                    if(any(x in key for x in rk_security_sensitive)):
                        processes[oid]["f_r5"] = int(processes[oid]["f_r5"] or 0) + 1

                if (typeValue == "REG_EXPAND_SZ"):
                    processes[oid]["f_r3"] = int(processes[oid]["f_r3"] or 0) + 1
                    if(any(x in key for x in rk_security_sensitive)):
                        processes[oid]["f_r6"] = int(processes[oid]["f_r6"] or 0) + 1

# xu ly event drop file
def handel_dropfile(processes, data):
    for r in data:
        oid = r["ProcessOID"]
        if( oid in processes):
            key = r["Filename"]
            # All TH
            processes[oid]["drop_all"] = int(processes[oid]["drop_all"] or 0) + 1
            processes[oid]["totalDropFileSize"] = processes[oid]["totalDropFileSize"] + r["Size"]
            # TH nhay cam
            if(any(x in key for x in drop_sensitive)):
                processes[oid]["drop_sensitive"] = int(processes[oid]["drop_sensitive"] or 0) + 1
                processes[oid]["totalDropSensiSize"] = int(processes[oid]["totalDropSensiSize"] or 0) + r["Size"]

# xu ly file
def handel_single_task(path):
    task_id = path.strip(".json").split("\\")[-1]
    if(os.path.getsize(path) / 1024 < 1) :
        raise
    data = json.load(open(path, encoding="utf8"))
    print(task_id)
    processes = init(task_id,data["Processes"])
    handel_priority(processes, data["Threats"])
    handle_ip(processes, data["Ips"])
    handel_domain(processes, data["Domain"])
    handel_http_request(processes, data["HttpRequests"])
    handel_registry(processes, data["Registries"])
    handel_dropfile(processes, data["DropFile"])
    handel_label(processes, data["Incidents"])
    return processes

def converse_to_csv(input_folder,save_path):
    tasks = glob.glob(input_folder + "/**/*.json")
    data = []
    for t in tasks:
        try:
            processes = list(handel_single_task(t).values())
            data = data + processes
        except:
            continue
    df = pd.DataFrame.from_dict(data)
    if(df.shape[0] > 0) :
        df = df.drop(['domains'], axis=1)
        ex = ["task", "CreationTimestamp", "label"]
        df["Scores_Network"] = df["Scores_Network"].astype(int)
        df["Autostart"] = df["Autostart"].astype(int)
        df["LowAccess"] = df["LowAccess"].astype(int)
        df = df.reindex(columns=(ex[:-1] + list([a for a in df.columns if not a in ex]) + [ex[-1]]))
        df.to_csv(save_path, index= False)
    else :
        print("empty")

converse_to_csv("input_demo_nor","final_0904_nor.csv")
