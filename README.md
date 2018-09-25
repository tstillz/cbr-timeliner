# Timeline Builder for Carbon Black Response
This tool is a quick script written to export tagged items within a specific Carbon Black Response investigation into timelines. 
These timelines can be ingested by the SOC/IR team for further analysis.

Writeup on this tool can be foud here: https://blog.stillztech.com/2018/09/carbon-black-response-timeliner.html

> Outputs all tagged events into a timeline (two export methods):
- All events per your investigation 
- Only events for the hostname specified

##### Usage
> Update `config.json` with your CBR URL, CBR API token and your investigation ID.

##### Running the script
> python3 main.py

##### Output
1) Hostname Specific
<hostname>_childproc.csv
<hostname>crossprocess.csv
<hostname>_filemod.csv
<hostname>_modload.csv
<hostname>_regmod.csv
<hostname>_timeline.csv -> All Events combined for a single host

2) All items in investigation
all_items_childproc.csv
all_items_crossprocess.csv
all_items_filemod.csv
all_items_modload.csv
all_items_regmod.csv
all_items_timeline.csv -> All Events combined for all tagged items in your investigation






