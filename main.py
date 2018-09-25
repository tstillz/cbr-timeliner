import requests
import json
requests.packages.urllib3.disable_warnings()

with open('config.json', 'r') as fd:
    cfg = json.load(fd)

cb_api = cfg.get('cb_api')
url = cfg.get('cb_url')

payload = {'X-Auth-Token': cb_api}
investigation = cfg.get('investigation_id')
full_url = url + "/api/tagged_event/" + investigation

##############

def host_lookup(hostname):
    try:
        get_sensor = requests.get(url + "/api/v1/sensor", headers=payload, verify=False)
        snr_lookup = get_sensor.json()

        for line in snr_lookup:
            snr_name = line.get('computer_name').lower()
            snr_id = str(line.get('id'))

            if (hostname == snr_name) or (hostname == snr_id):
                jj = {"result": 1,
                      "hostname": snr_name,
                      "id": snr_id
                      }
                return jj

        jj = {"result": 0}
        return jj

    except Exception as e:
        print(e)

def generate_timeline(hostname=None):

    if hostname == None:
        hostname = "all_items"

    master_timeline = hostname + "_master.csv"
    file_cldprc = hostname + "_childproc.csv"
    file_crsproc = hostname + "_crossprocess.csv"
    file_ml = hostname + "_modload.csv"
    file_fm = hostname + "_filemod.csv"
    file_rm = hostname + "_regmod.csv"
    file_nc = hostname + "_netconn.csv"

    with open(master_timeline, 'w') as mas:
        mas.write("Timestamp | Type | hostname | Description \n")

    with open(file_cldprc, 'w') as cldp:
        cldp.write( "hostname| start time | PID | process name | process path| arguments | MD5| username | PPID| parent name| parent path  \n")

    with open(file_crsproc, 'w') as crossprc:
        crossprc.write("hostname| timestamp| accessor name| accessor path| access type| accessing | md5 | description\n")

    with open(file_ml, 'w') as ml:
        ml.write("hostname| timestamp| process name| process path| modload file| MD5| signature| description \n")

    with open(file_fm, 'w') as fm:
        fm.write("hostname| timestamp| file path| action| writer| writer name| description \n")

    with open(file_rm, 'w') as rm:
        rm.write("hostname| timestamp| action| path| process name| process path| description \n")

    with open(file_nc, 'w') as nc:
        nc.write("hostname| timestamp| process name| process path| dst address| port| protocol| type| description \n")

    get_items = requests.get(full_url, headers=payload, verify=False)
    get_done = get_items.json()

    for items in get_done:
        event_type = items.get('event_type')
        event_data = items.get('event_data')
        ddx = json.loads(event_data)
        host = ddx.get('hostname').lower()

        if hostname != "all_items":
            if hostname != host:
                continue

        if event_type == "childproc":
            start1 = ddx.get('start_date').replace('T', ' ').replace('Z', '')
            process_md5 = ddx.get('md5')
            proc_pid = ddx.get('pid')
            proc_name = ddx.get('pathWithMarker').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')
            path = ddx.get('fields').get('path')
            md5 = ddx.get('fields').get('md5')
            commandLine = ddx.get('fields').get('commandLine')
            username = ddx.get('fields').get('username')

            ## Let try and fetch the orginal process data, else we just use the data from the tagged event itself
            try:
                alz_id = ddx.get('analyze_link')
                alz_clean = alz_id.replace("#/analyze", "").replace("/1?cb.legacy_5x_mode=false", "")

                get_args_go = requests.get(url + "/api/v1/process" + alz_clean, headers=payload, verify=False)
                get_args = get_args_go.json()

                parent_process_pid = get_args.get('process').get('parent_pid')
                parent_process_name = get_args.get('parent').get('process_name').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')
                parent_path = get_args.get('parent').get('path')

                process_pid = get_args.get('process').get('process_pid')
                username = get_args.get('process').get('username')
                process_name = get_args.get('process').get('process_name').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')
                path = get_args.get('process').get('path')
                start2 = get_args.get('process').get('start').replace('T', ' ').replace('Z', '')
                process_md5 = get_args.get('process').get('process_md5')
                cmdline = get_args.get('process').get('cmdline')

                ## Write to its own file per event type
                with open(file_cldprc, 'a+') as cld:
                    cld.write('|'.join(map(str, [host, start2, process_pid, process_name, path, cmdline, process_md5, username, parent_process_pid, parent_process_name, parent_path]))+ "\n")

                ## Write to the master timeline
                with open(master_timeline, 'a+') as ma:
                    master_desc = "Process_PID: "+str(proc_pid)+" Process_Name: "+proc_name+" Cmdline: " + cmdline+" Process_MD5: "+process_md5+" Parent_Process_Name: " + parent_process_name
                    ma.write('|'.join(map(str, [start1, event_type, host, master_desc]))+ "\n")

            except Exception as e:
                print("Original childproc process event is gone, using the process investigation data instead.")
                ## Write to its own file with limited fields
                with open(file_cldprc, 'a+') as cld:
                    cld.write('|'.join(map(str, [host, start1, proc_pid, proc_name,path,commandLine, md5, username]))+ "\n")

                ## Write to master with limited fields
                cp_desc_bucket = "Process_PID: "+proc_pid+" Process_Name: "+proc_name+" Process_MD5: "+process_md5
                with open(master_timeline, 'a+') as ma:
                    ma.write('|'.join(map(str, [start1, event_type, host, cp_desc_bucket]))+ "\n")

        elif event_type == "modload":
            sig = ddx.get('signature_str')
            description = ddx.get('description')
            process_path = ddx.get('path')
            process_name = ddx.get('process_name').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')
            timestamp = ddx.get('start_date').replace('T', ' ').replace('Z', '')
            md5 = ddx.get('md5')
            modload_filename = ddx.get('fields')[2]

            # Individual file modloads
            with open(file_ml, 'a') as ml:
                ml.write('|'.join(map(str, [host, timestamp, process_name, process_path, modload_filename, md5, sig, description]))+"\n")

            # Write to master timeline
            ml_mast_desc = "Modload File: " + modload_filename + " MD5: " + md5 + " Process Path: " + process_path
            with open(master_timeline, 'a') as ma:
                ma.write('|'.join(map(str, [timestamp, event_type, host, ml_mast_desc]))+ "\n")

        elif event_type == "crossproc":
            timestamp = ddx.get('start').replace('T', ' ').replace('Z', '')
            accessor_name = ddx.get('process_name').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')
            accessor_path = ddx.get('path').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')
            access_type = ddx.get('procTypeWithMarker')
            accessing = ddx.get('pathForRender')
            description = ddx.get('description')
            md5 = ddx.get('md5')

            with open(file_crsproc, 'a') as cp:
                cp.write('|'.join(map(str, [host, timestamp, accessor_name, accessor_path, access_type, accessing, md5, description]))+ "\n")

            #event_type, hostname, start, description, md5
            crossp_mast_desc = "Accessor Name: " + accessor_name + " Accessor Path: " + accessor_path + " Access Type: " + access_type + " Accessing: " + accessing

            with open(master_timeline, 'a') as ma:
                ma.write('|'.join(map(str, [timestamp, event_type, host, crossp_mast_desc]))+ "\n")

        elif event_type == "filemod":
            start_date = ddx.get('start_date').replace('T', ' ').replace('Z', '')
            action = ddx.get('fmAction')
            description = ddx.get('description').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')
            writer_name = ddx.get('process_name').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')
            file_path = ddx.get('pathWithMarker').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')
            writer = ddx.get('path')

            with open(file_fm, 'a') as fm:
                fm.write('|'.join(map(str, [host, start_date, file_path, action, writer, writer_name, description]))+ "\n")

            #event_type, hostname, start, description, md5
            with open(master_timeline, 'a') as ma:
                fm_master = "Action: " + action + " File Path: " + file_path + " Writer: " + writer
                ma.write('|'.join(map(str, [start_date, event_type, host, fm_master]))+ "\n")

        elif event_type == "regmod":
            timestamp = ddx.get('start_date').replace('T', ' ').replace('Z', '')
            action = ddx.get('rmAction')
            reg_path = ddx.get('pathWithMarker').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')
            proc_path = ddx.get('path')
            proc_name = ddx.get('process_name').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')
            description = ddx.get('description').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')

            ### add to only the specific event type
            with open(file_rm, 'a') as rm:
                rm.write('|'.join(map(str, [host, timestamp, action, reg_path, proc_name, proc_path, description]))+ "\n")

            #add to master timeline
            with open(master_timeline, 'a') as ma:
                reg_mastr = "Action: " +action+ " Path: " +reg_path + " Process Path: " + proc_path
                ma.write('|'.join(map(str, [timestamp, event_type, host, reg_mastr]))+ "\n")

        elif event_type == "netconn":
            timestamp = ddx.get('start').replace('T', ' ').replace('Z', '')
            process_name = ddx.get('process_name').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')
            process_path = ddx.get('path').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')
            dst_ip = ddx.get('address')
            dst_port = ddx.get('remotePort')
            dst_proto = ddx.get('protocol_str')
            conn_type = ddx.get('outbound')

            if conn_type == True:
                conn = "outbound"
            elif conn_type == False:
                conn = "Inbound"
            else:
                conn = "unknown"

            desc = ddx.get('description').replace('PREPREPRE', '').replace('POSTPOSTPOST', '')

            ## Write to single event section
            with open(file_nc, 'a') as nc:
                nc.write('|'.join(map(str, [host, timestamp, process_name, process_path, dst_ip, dst_port, dst_proto, conn, desc]))+ "\n")

            #Write to master timeline
            nc_master = ("DstSocket: " + str(dst_ip) + ":" + str(dst_port) + " Protocol: " + str(dst_proto) + " Type: " +str(conn_type)+ " Process Path:" + str(process_path))
            with open(master_timeline, 'a') as ma:
                ma.write('|'.join(map(str, [timestamp, event_type, host, nc_master]))+ "\n")

def main():
    print('Carbon Black Response Timeline Builder \n ')
    print('1) Single Host Timeline')
    print('2) Master Timeline - "ALL TAGGED EVENTS" ')

    all_or_one = input("Selection:")

    if all_or_one == "1":
        hostname = input("Please enter the hostname or sensor ID:")
        hostExists = host_lookup(hostname)
        if hostExists.get("result") == 1:
            generate_timeline(hostname)
        else:
            print("Hostname not found.\n")
            main()

    elif all_or_one == "2":
        generate_timeline()

    else:
        print("Invalid choice.")
        main()

if __name__ == '__main__':
    main()




