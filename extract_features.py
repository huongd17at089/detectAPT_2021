import pandas as pd
import json
from builtins import any
import glob

# constant
features = ["ip", "domain", "http_request"]
levels = ["unknown", "Suspicious", "Malicious", "whitelist", "unsafe"]
registry_features = ["HKEY_LOCAL_MACHINE", "HKEY_CLASSES_ROOT", "HKEY_USERS", "HKEY_CURRENT_CONFIG", "HKEY_CURRENT_USER",
                     "startup_registry_keys","active_setup_registry_keys", "services_registry_keys", "dll_injection_registry_keys", "shell_spawning_registry_keys", "internet_settings_registry_keys", "bho_registry_keys"]
registry_keys = {
    "startup_registry_keys" : ["CurrentVersion\RunServices","CurrentVersion\RunServicesOnce","CurrentVersion\Run","CurrentVersion\RunOnce","CurrentVersion\RunOnceEx"],
    "active_setup_registry_keys" : ["Microsoft\Active Setup"],
    "services_registry_keys" : ["CurrentControlSet\Services"],
    "dll_injection_registry_keys" : ["Windows\AppInit_DLLs","Session Manager\AppCertDLLs","Windows\LoadAppInit_DLLs"],
    "shell_spawning_registry_keys" : ["exefile\shell\Open\command","comfile\shell\Open\command","batfile\shell\Open\command","htafile\Shell\Open\Command","piffile\shell\Open\command"],
    "internet_settings_registry_keys" : ["CurrentVersion\Internet Settings"],
    "bho_registry_keys" : ["Explorer\Browser Helper Objects"]
}

def init(task_id,data):
    process = {}
    for p in data :
        key = p["OID"]
        p.pop("OID")
        p.update({"Priority" : 0})
        p.update({"task": task_id})
        p.update({"domains": []})
        for f in features:
            for l in levels:
                p.update({l + "_" + f: 0})
        for r in registry_features:
            p.update({r: 0})
        p.update({"label" : 0})
        process.update({key: p})
    return process


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

def handel_registry(processes, data):
    # print(data[0])
    for r in data:
        oid = r["ProcessOID"]
        if( oid in processes):
            # 5 HKEY type
            feature_name = r["Key"].split("\\")[0]
            new_val = int(processes[oid].get(feature_name) or 0) + 1
            processes[oid][feature_name] = new_val
            # check 7 security-sensitive registry keys
            key = r["Key"]
            for k in registry_keys:
                if(any(x in key for x in registry_keys[k])):
                    processes[oid][k] = 1
                    break


def handel_label(processes, incidents):
    for inc in incidents:
        oid = inc["ProcessOID"]
        if (oid in processes):
            new_val = max(processes[oid]["label"], int(inc["ThreatLevel"]) + 1)
            processes[oid]["label"] = new_val

def handel_priority(processes, threats):
    for thr in threats:
        oid = thr["ProcessOID"]
        if (oid in processes):
            new_val = max(processes[oid]["Priority"], int(thr["Priority"]) + 1)
            processes[oid]["Priority"] = new_val

def handel_single_task(path):
    task_id = path.strip(".json").split("\\")[-1]
    print(task_id)
    data = json.load(open(path, encoding="utf8"))
    processes = init(task_id,data["Processes"])
    handle_ip(processes, data["Ips"])
    handel_domain(processes, data["Domain"])
    handel_registry(processes, data["Registries"])
    handel_http_request(processes, data["HttpRequests"])
    handel_label(processes, data["Incidents"])
    handel_priority(processes, data["Threats"])
    return processes


def converse_to_csv(input_folder,save_path):
    tasks = glob.glob(input_folder + "/*.json")
    data = []
    for t in tasks:
        data = data + list(handel_single_task(t).values())
    df = pd.DataFrame.from_dict(data)
    df = df.drop(['domains'], axis=1)
    ex = ["task", "CreationTimestamp", "label"]
    df = df.reindex(columns=(ex[:-1] + list([a for a in df.columns if not a in ex]) + [ex[-1]]))
    df.to_csv(save_path, index= False)

converse_to_csv("input_folder","final_demo.csv")
















