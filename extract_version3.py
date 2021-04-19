import pandas as pd
import json
from builtins import any
import glob
import os

# constant
features = ["ip", "dns", "req"]
levels = ["unkn", "Susp", "Mali", "wlist", "unsa"]




#######################_________new feature 1_________#######################
registry_features_huong = ["HKEY_LOCAL_MACHINE", "HKEY_CLASSES_ROOT", "HKEY_USERS", "HKEY_CURRENT_CONFIG", "HKEY_CURRENT_USER",
                            "startup_registry_keys","active_setup_registry_keys", "services_registry_keys", "dll_injection_registry_keys",
                           "shell_spawning_registry_keys", "internet_settings_registry_keys", "bho_registry_keys"]
registry_keys = {
    "startup_registry_keys" :           ["CurrentVersion\RunServices","CurrentVersion\RunServicesOnce","CurrentVersion\Run","CurrentVersion\RunOnce",
                                        "CurrentVersion\RunOnceEx"],
    "active_setup_registry_keys" :      ["Microsoft\Active Setup"],
    "services_registry_keys" :          ["CurrentControlSet\Services"],
    "dll_injection_registry_keys" :     ["Windows\AppInit_DLLs","Session Manager\AppCertDLLs","Windows\LoadAppInit_DLLs"],
    "shell_spawning_registry_keys" :    ["exefile\shell\Open\command","comfile\shell\Open\command","batfile\shell\Open\command",
                                        "htafile\Shell\Open\Command","piffile\shell\Open\command"],
    "internet_settings_registry_keys":  ["CurrentVersion\Internet Settings"],
    "bho_registry_keys" :               ["Explorer\Browser Helper Objects"]
}

dropfile_feature = ["executable","text", "html", "image","xml","$WinREAgent", "OneDriveTemp", "PerfLogs", "Program Files", "Program Files(x86)",
                    "ProgramData","Windows",  "$RECYCLE.BIN", "Users"]
dropfile_fe = ["executable","text", "html", "image","xml"]
drop_file = {
    "$WinREAgent": ["&WinREAgent"],
    "OneDriveTemp": ["OneDriveTemp"],
    "PerfLogs": ["PerfLogs"],
    "Program Files": ["Program Files"],
    "Program Files(x86)": ["Program Files(x86)"],
    "ProgramData": ["ProgramData"],
    "Windows": ["Windows"],
    "$RECYCLE.BIN": ["$RECYCLE.BIN"],
    "Users": ["Microsoft\Windows\Temporary Internet Files","Microsoft\CryptnetUrlCache", "Roaming\Macromedia", "Default\Cookies"]
}

#######################_________end feature 1_________#######################


#######################_________new feature 2_________#######################
registry_features = ["f_r1", "f_r2", "f_r3", "f_r4", "f_r5", "f_r6", "f_r7", "f_rscore"]

# 7 nhóm security-sensitive registry keys
rk_security_sensitive = [
    "CurrentVersion\RunServices","CurrentVersion\RunServicesOnce","CurrentVersion\Run",
    "CurrentVersion\RunOnce","CurrentVersion\RunOnceEx",
    "Microsoft\Active Setup",
    "CurrentControlSet\Services",
    "Windows\AppInit_DLLs","Session Manager\AppCertDLLs","Windows\LoadAppInit_DLLs",
    "exefile\shell\Open\command","comfile\shell\Open\command","batfile\shell\Open\command",
    "htafile\Shell\Open\Command","piffile\shell\Open\command"
    "CurrentVersion\Internet Settings",
    "Explorer\Browser Helper Objects"
]

rk_mitre = ["T1112", "T1012", "T1547", "T1060"]

# path file nhay cam
drop_sensitive = [
    "Program Files", "Program Files (x86)"
    "Windows", "Temp", "Roaming\Macromedia", "Default\Cookies",
    "Windows\Temporary Internet Files", "Microsoft\CryptnetUrlCache"
]

# cmd feature danh gia theo ma mitre atack
cmd_sensitive = ["T1059"]

# name feature with ip, domain, http
ip_port = [80, 503]
ip_featuer = ["f_tcp", "f_tcpSen", "f_udp", "f_udpSen"]
ip_packet = ["f_tcpsend", "f_tcpsendSe", "f_tcprecv", "f_tcprecvSe", "f_udpsend", "f_udpsendSe", "f_udprecv", "f_udprecvSe"]

req_feature = ["ReqGET", "ReqPOST", "ReqAnother", "Req"]

dns_feature = ["DNS_1", "DNS_0"]


#######################_________end feature 2_________#######################


#######################_________code feature 1_________#######################

def init(task_id,data):
    process = {}
    for p in data :
        key = p["OID"]
        p.pop("OID")
        p.update({"Priority" : 0,"task": task_id, "domains": [], "label" : 0, "totalDropFileSize" : 0 })
        for f in features:
            for l in levels:
                p.update({l + "_" + f: 0})
        for r in registry_features_huong:
            p.update({r: 0})
        for t in dropfile_feature:
            p.update({t : 0})
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

def handel_dropfile(processes, data):
    for r in data:
        oid = r["ProcessOID"]
        if( oid in processes):
            key1 = r["ContentType"]
            if( key1 in dropfile_fe) :
                new_val = int(processes[oid].get(key1) or 0) + 1
                processes[oid][key1] = new_val
            key = r["Filename"]
            for k in drop_file:
                if(any(x in key for x in drop_file[k])):
                    # new_val = 1
                    processes[oid][k] = 1
                    break
            processes[oid]["totalDropFileSize"] =  processes[oid]["totalDropFileSize"] + r["Size"]

#######################_________end code feature 1_________#######################


#######################_________code feature 2_________#######################
def init_new(task_id,data):
    process = {}
    for p in data :
        key = p["OID"]
        p.pop("OID")
        p.update({"Priority" : 0,"task": task_id, "domains": [], "cmd_score" : 0, "label" : 0 })
        for f_ip in ip_featuer:
            for l in levels:
                p.update({f_ip + "_" + l: 0})
        for f_dns in dns_feature:
            for l in levels:
                p.update({f_dns + "_" + l: 0})
        for f_req in req_feature:
            for l in levels:
                p.update({f_req + "_" + l: 0})
        for f_pak in ip_packet:
            for l in levels:
                p.update({f_pak + "_" + l: 0})
        for r in registry_features:
            p.update({r: 0})
        p.update(
            {"drop_all": 0, "totalDropFileSize": 0, "drop_sensitive": 0, "totalDropSensiSize": 0 })
        process.update({key: p})
    return process


# So luong ip cho feature dc dinh nghia
def handle_ip_detail(processes, data):
    for ip in data:
        oid = ip["ProcessOID"]
        if oid in processes:
            # lay level cho ip
            domains = processes[oid]["domains"]
            domains.append(ip["Domain"])

            # # xet TH theo phuong thuc ket noi va port
            # phuong thuc TCP/UDP
            prot = ip["Prot"]
            port = ip["Port"]
            level = levels[ip["Type"]]
            send = ip["Send"]
            recv = ip["Recv"]

            # C1_...
            # port = str(ip["Port"]) if ip["Port"] in ip_port else "other"
            # feature_name = "IP" + "_".join([prot, port, level])
            # new_val = int(processes[oid].get(feature_name) or 0) + 1
            # processes[oid][feature_name] = new_val

            if(prot == "tcp"):
                if(port == 80 or port == 443):
                    feature_name_tsensi = "f_tcpSen_" + level
                    feature_name_send = "f_tcpsendSe_" + level
                    feature_name_recv = "f_tcprecvSe_" + level
                    processes[oid][feature_name_tsensi] = int(processes[oid].get(feature_name_tsensi) or 0) + 1
                    processes[oid][feature_name_send] = int(processes[oid].get(feature_name_send) or 0) + send
                    processes[oid][feature_name_recv] = int(processes[oid].get(feature_name_recv) or 0) + recv
                else:
                    feature_name = "f_tcp_" + level
                    feature_name_send = "f_tcpsend_" + level
                    feature_name_recv = "f_tcprecv_" + level
                    processes[oid][feature_name] = int(processes[oid].get(feature_name) or 0) + 1
                    processes[oid][feature_name_send] = int(processes[oid].get(feature_name_send) or 0) + send
                    processes[oid][feature_name_recv] = int(processes[oid].get(feature_name_recv) or 0) + recv
            elif(prot == "udp"):

                if(port == 80 or port == 443):
                    feature_name_usensi = "f_udpSen_" + level
                    feature_name_send = "f_udpsendSe_" + level
                    feature_name_recv = "f_udprecvSe_" + level
                    processes[oid][feature_name_usensi] = int(processes[oid].get(feature_name_usensi) or 0) + 1
                    processes[oid][feature_name_send] = int(processes[oid].get(feature_name_send) or 0) + send
                    processes[oid][feature_name_recv] = int(processes[oid].get(feature_name_recv) or 0) + recv
                else:
                    feature_name = "f_udp_" + level
                    feature_name_send = "f_udpsend_" + level
                    feature_name_recv = "f_udprecv_" + level
                    processes[oid][feature_name] = int(processes[oid].get(feature_name) or 0) + 1
                    processes[oid][feature_name_send] = int(processes[oid].get(feature_name_send) or 0) + send
                    processes[oid][feature_name_recv] = int(processes[oid].get(feature_name_recv) or 0) + recv

def handel_domain_detail(processes, data):
    domain_data_sta0 = {}
    domain_data_sta1 = {}

    for d in data:
        domain = d["Domain"]
        status = d["Status"]
        if not domain in domain_data_sta0:
            domain_data_sta0.update({domain: 0})
            domain_data_sta1.update({domain: 0})
        if(status == 1):
            domain_data_sta1[domain] = max(domain_data_sta1[domain], d["Type"] +1)
        else:
            domain_data_sta0[domain] = max(domain_data_sta1[domain], d["Type"]+1)
    for p in processes:
        process = processes[p]
        domains = process["domains"]
        for d in domains:
            if(d in domain_data_sta1):
                feature_name = "DNS_1_" + levels[domain_data_sta1[d] - 1]
                new_val = int(process[feature_name] or 0) + 1
                process[feature_name] = new_val
            if(d in domain_data_sta0):
                feature_name = "DNS_0_" + levels[domain_data_sta0[d] - 1]
                new_val = int(process[feature_name] or 0) + 1
                process[feature_name] = new_val

def handel_request_detail(processes,data):
    for http_req in data:
        oid = http_req["ProcessOID"]
        level_req = levels[http_req["Type"]]
        if oid in processes:
            method = http_req["Method"]
            if(method == "GET"):
                feature_name = "ReqGET_" + level_req
                new_val = int(processes[oid].get(feature_name) or 0) + 1
                processes[oid][feature_name] = new_val
            elif(method == "POST"):
                feature_name = "ReqPOST_" + level_req
                new_val = int(processes[oid].get(feature_name) or 0) + 1
                processes[oid][feature_name] = new_val
            else:
                feature_name = "ReqAnother_" + level_req
                new_val = int(processes[oid].get(feature_name) or 0) + 1
                processes[oid][feature_name] = new_val
        if(oid == ""):
            feature_name = "Req_" + level_req
            new_val = int(processes[oid].get(feature_name) or 0) + 1
            processes[oid][feature_name] = new_val

# lay gia tri max cua label, cmd
def handel_label_detail(processes, incidents):
    for inc in incidents:
        oid = inc["ProcessOID"]
        if (oid in processes):
            # label = max threatlevel
            new_val = max(processes[oid]["label"], int(inc["ThreatLevel"]) + 1)
            processes[oid]["label"] = new_val
            
            mitre = inc["MitreAttacks"]
            # cmd = max threatlevel(cmd_sensitive)
            if (any(x in mitre for x in cmd_sensitive)):
                processes[oid]["cmd_score"] = max(int(processes[oid]["cmd_score"]), int(inc["ThreatLevel"]) + 1)
            
            # f_rscore = max threatlevel(rk_mitre)
            if (any(x in mitre for x in rk_mitre)):
                processes[oid]["f_rscore"] = max(int(processes[oid]["f_rscore"]), int(inc["ThreatLevel"]) + 1)

# lay gia tri max cua priority
def handel_priority_detail(processes, threats):
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
# f_r7 TH còn lại
# f_rscore xếp loại (lấy max) theo mitre đánh giá
def handel_registry_detail(processes, data):
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
            else:
                processes[oid]["f_r7"] = int(processes[oid]["f_r7"] or 0) + 1

# xu ly event drop file
def handel_dropfile_detail(processes, data):
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


#######################_________end code feature 2_________#######################

# xu ly file
def handel_single_task(path):
    task_id = path.strip(".json").split("\\")[-1]
    if(os.path.getsize(path) / 1024 < 1) :
        raise
    data = json.load(open(path, encoding="utf8"))
    print(task_id)
    processes = init_new(task_id,data["Processes"])
    handel_priority_detail(processes, data["Threats"])
    handle_ip_detail(processes, data["Ips"])
    handel_domain_detail(processes, data["Domain"])
    handel_request_detail(processes, data["HttpRequests"])
    handel_registry_detail(processes, data["Registries"])
    handel_dropfile_detail(processes, data["DropFile"])
    handel_label_detail(processes, data["Incidents"])
    return processes

def converse_to_csv(input_folder,save_path):
    tasks = glob.glob(input_folder + "/*.json")
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

converse_to_csv("input_demo_nor","final_1904_nor.csv")
