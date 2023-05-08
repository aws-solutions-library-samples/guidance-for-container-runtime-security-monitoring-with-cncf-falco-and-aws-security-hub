import json
import boto3
import uuid
import datetime
import base64
import gzip

PARTITION="aws"

session = boto3.session.Session()
ec2 = session.resource("ec2")
sts = session.client('sts')
ecs = session.client('ecs')

#Get EC2 instance by its ID
def get_ec2_details(instance_id):
        instance = ec2.Instance(instance_id)
        #print("get_ec2_details got instance: ",instance)
        return instance
    
#Get account ID 
def get_account_id():

    caller = sts.get_caller_identity()
    return caller.get("Account")

#https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.describe_tasks
def get_ecs_details(ecs_cluster, ecs_task):
    response = ecs.describe_tasks(cluster=ecs_cluster, tasks=[ecs_task])
    #get 1st response from 'tasks' and get its details
    task = response["tasks"][0]
    az = task["availabilityZone"]
    created = task["createdAt"]
    container_resources = []
    for container in task["containers"]:

        resource = {}
        resource["Type"] = "Container"
        resource["Id"] = container["runtimeId"]
        resource["Details"] = {}
        resource["Details"]["Container"] = {}
        resource["Details"]["Other"] = {}
        resource["Details"]["Other"]["containerArn"] = container["containerArn"]
        resource["Details"]["Other"]["taskArn"] = container["taskArn"]
        resource["Details"]["Other"]["containerRuntime"] = container["runtimeId"]
       
       
        resource["Details"]["Container"]["ImageName"] = container["image"]
        if 'imageDigest' in resource:
            resource["Details"]["Container"]["ImageId"] = container["imageDigest"]
        resource["Details"]["Container"]["Name"] = container["name"]

        container_resources.append(resource)

    task_resource = {}
    task_resource["Id"] = task["taskArn"]
    task_resource["Type"] = "Other"
  

    container_resources.append(task_resource)

    cluster_resource = {}
    cluster_resource["Id"] = ecs_cluster
    cluster_resource["Type"] = "Other"

    container_resources.append(cluster_resource)

    return container_resources

#https://falco.org/docs/rules/
def map_finding_severity(priority):

    severity = {
        "EMERGENCY": "CRITICAL",
        "ALERT": "CRITICAL",
        "CRITICAL": "CRITICAL",
        "ERROR": "HIGH",
        "WARNING": "HIGH",
        "NOTICE": "MEDIUM",
        "INFORMATIONAL": "INFORMATIONAL",
        "DEBUG": "INFORMATIONAL"
    }

    label = severity.get(priority.upper(), "INFORMATIONAL")
    sev = {}
    sev["Label"] = label
    sev["Original"] = priority
    return sev

#generate ID based on region and account_id parameters
def generate_id(account_id,region):
    suffix = "falco-" + uuid.uuid1().hex
    full_id = f"{region}/{account_id}/{suffix}"
    return full_id


#get IP address for an instance
def get_ip_address(instance):

    ip = []
    if instance.public_ip_address:
        ip.append(instance.public_ip_address)
    if instance.private_ip_address:
        ip.append(instance.private_ip_address)

    return ip
    
#Function that creates and fills in EC2 Instance resource based on parameters of instance object
def create_ec2_instance_resource(instance):
    region = session.region_name
    instance_resource = {}
    instance_resource["Details"] = {}
    instance_resource["Type"] = "AwsEc2Instance"
    instance_resource["Id"] = instance.instance_id
    instance_resource["Partition"] = PARTITION
    instance_resource["Region"] = region
    instance_resource["Details"]["AwsEc2Instance"] = {}
    instance_resource["Details"]["AwsEc2Instance"]["Type"] = instance.instance_type
    instance_resource["Details"]["AwsEc2Instance"]["LaunchedAt"] = instance.launch_time.isoformat(timespec='milliseconds')

    ip = get_ip_address(instance)
    
    instance_resource["Details"]["AwsEc2Instance"]["IpV4Addresses"] = ip
    instance_resource["Details"]["AwsEc2Instance"]["SubnetId"] = instance.subnet_id
    instance_resource["Details"]["AwsEc2Instance"]["VpcId"] = instance.vpc_id
    instance_resource["Details"]["AwsEc2Instance"]["IamInstanceProfileArn"] = instance.iam_instance_profile["Arn"]
    
  
    return instance_resource
    
#Function that converts ECS Falco log entry to ASFF format
def ecs_convert_falco_log_to_asff(entry):
    
    #sample ECS log entry - NO ERROR
    # {
    # "container_id": "2b07c061f4552e55438ebc385191976e20e34bc8f72f05833e11ea2a63546543",
    # "container_name": "/ecs-Falco-3-falco-9c82bad1ccdf92813a00",
    # "ec2_instance_id": "i-0279e51d31fa06571",
    # "ecs_cluster": "awsome_ecs_cluster",
    # "ecs_task_arn": "arn:aws:ecs:us-west-1:133776528597:task/awsome_ecs_cluster/dfc4b0b8d9554e54a36d4af3e5165889",
    # "ecs_task_definition": "Falco:3",
    # "log": "* Trying to dkms install falco module with GCC /usr/bin/gcc-6",
    # "source": "stdout"
    # }
    
    region = session.region_name
    #instance_id = entry["ec2_instance_id"]
    #instance = get_ec2_details(instance_id)
    instance_id = None
    instance = None
    # Starting try-catch block
    try: 
      instance_id = entry["ec2_instance_id"]
      #print("CHECK: ECS to ASFF got instance_id: ",instance_id)
      instance = get_ec2_details(instance_id)
    except:
      print("PROBLEM: ECS to ASFF looks like there's no element for 'ec2_instance_id'")
      
    finally:
      print("TEST: ECS to ASFF got EC2 instance: ", instance)   
    # ending try-catch block
    
    # parse 'log' element 
    logEntry = None
    severity = None
    
    try: 
       # in cases of no exceptions 'log' may not be JSON formatted    
       logEntry = json.loads(entry["log"]) 
       severity = map_finding_severity(logEntry["priority"])
    except:
       print("PROBLEM: ECS to ASFF looks like there's no 'log' with 'priority' elements inside it - likely no error! ", entry["log"], severity)
       return None
    
    #if no   
    print ("NB!!! DEBUG: ECS to ASFF parsed log LOG DATA type, contents: ", type(logEntry), logEntry )
    print ("---------------------------------------------")
    
    # get account ID and derived objects
    account_id= get_account_id()
    this_id = generate_id(account_id,region)
    print ("CHECK: ECS to ASFF got account ID, this_id ", account_id, this_id)
    
    #check whether instance is null or not
    if instance is None:
       print("ECS to ASFF - Could not get instance_resource from NULL instance!") 
       return None
    else:
       instance_resource = create_ec2_instance_resource(instance)     
    
    #Obtain ECS resources using ECS c luster and task details
    ecs_resources = get_ecs_details(entry["ecs_cluster"], entry["ecs_task_arn"])
    
    # Initalize and append created instance_resource to an array resources[]
    resources = []
    resources.append(instance_resource)

    for container_resource in ecs_resources:
        resources.append(container_resource)

    #Initialize and start building ASFF finding array
    finding = {}
    finding["SchemaVersion"] = "2018-10-08"
    finding["AwsAccountId"] = account_id
    finding["Id"] = this_id
    #DZ; added for AB3
    finding["CompanyName"] = "AnyCompany"
    finding["Description"] = str(logEntry["output"])
    finding["GeneratorId"] = instance_id + "-" + this_id.split("/")[-1]
    finding["ProductArn"] = f"arn:{PARTITION}:securityhub:{region}:{account_id}:product/{account_id}/default"
    finding["Severity"] = severity
    finding["Resources"] = resources
    finding["Title"] = logEntry["rule"]
    finding["Types"] = ["Container Software and Configuration Checks"]
    now = datetime.datetime.now()
    #Lambda is UTC
    finding["UpdatedAt"] = f"{now.isoformat(timespec='milliseconds')}Z"
    finding["CreatedAt"] = f"{now.isoformat(timespec='milliseconds')}Z"

    return finding


# Retrieve details of EKS Falco log message entry obtained from 'ouput_fields element'

def get_eks_details(message):

    #log = message["log"]
    #DZ: sample section format
    #"output_fields": {
#        "container.id": "f687a1640776",
#        "container.image.repository": "docker.io/library/nginx",
#        "evt.time": 1677545313548344774,
#        "fd.name": "/etc/671",
#        "k8s.ns.name": "default",
#        "k8s.pod.name": "nginx-test2",
#        "proc.aname[2]": null,
#        "proc.aname[3]": null,
#        "proc.aname[4]": null,
#        "proc.cmdline": "touch /etc/671",
#        "proc.name": "touch",
#        "proc.pcmdline": "bash",
#        "proc.pid": 31576,
#        "proc.pname": "bash",
#        "user.loginuid": -1,
#        "user.name": "<NA>"
#    }
    print("-------------------------------------------")
    
    fields = None
    try: 
       #fields = log["output_fields"]
       #print ("DEBUG: In get_eks_details RAW Data type of message, output_fields: ", type(message), message["output_fields"])
       fields = message["output_fields"]
       print ("DEBUG: get EKS details log 'output_fields' data type, values are: ", type(fields), fields)
       
    except:
       print("PROBLEM: get EKS details - looks like there's no log element for 'output_fields'?")
      
    finally:
       #print("CHECK: get_eks_details got output_fields: ", fields)  
       print("----------------------------------------------------")
    
    container_id = "test"
    pod_name = "test"
    namespace = "test"
    image = "test"
    
    # output = str(logEntry["output"])
    #check if fields elements has values   
    if fields is None:
       print("PROBLEM get_eks_details - no data for 'output_fields', cannot retrieve details! ", fields)    
    else:    
       try:
          container_id = fields["container.id"]
          pod_name = fields["k8s.pod.name"]
          namespace = fields["k8s.ns.name"]
          image = fields["container.image.repository"]
       except:
          print("PROBLEM: get EKS details - looks like there's no EXPECTED container element in 'output_fields' above!")
       finally:
          print ("DEBUG: get EKS details - Container details (partially) retrieved from 'output_fields'") 
          print ("-------------------------------------------------------------------------")
          
    #initialize and start forming resources array
    resources = []
    resource = {}
    resource["Type"] = "Container"
    resource["Id"] = container_id
    resource["Details"] = {}
    resource["Details"]["Container"] = {}
    resource["Details"]["Other"] = {}
    resource["Details"]["Other"]["podName"] = pod_name
    resource["Details"]["Other"]["namespaceName"] = namespace
    resource["Details"]["Container"]["ImageName"] = image

    resources.append(resource)
    return resources


# Convert EKS Falco log message to AWS ASFF format
# refer examples from here: https://www.freecodecamp.org/news/python-json-how-to-convert-a-string-to-json

def eks_convert_falco_log_to_asff(entry):
    region = session.region_name
    
    # intialize instance variables
    instance_id = None
    instance = None
    # Starting try-catch block
    try: 
      instance_id = entry["ec2_instance_id"]
      instance = get_ec2_details(instance_id)
      print("DEBUG: EKS to ASFF: got instance_id, instance: ",instance_id,instance)
    except:
      print("PROBLEM: EKS to ASFF: looks like there's no element for 'ec2_instance_id'")
   
    finally:
      #print("EKS to ASFF got ec2_instance: ", instance)
      print("-------------------------------------------")
    # ending try-catch block
    
    #get AWDS account ID
    account_id= get_account_id()
    
    #generate ID for this object
    this_id = generate_id(account_id,region)
    # print ("EKS to ASFF got account ID, this_id ", account_id, this_id)
    

    # DZ: initialize log Entry and handle cases when it doesn't contain JSON exception like
    # "log": "Fri Mar 17 17:52:26 2023: libcurl error: Couldn't resolve host name",
    logEntry = None
    try: 
       #output = entry["log"]["output"]
       logEntry = json.loads(entry["log"])
       # DZ: after getting clean JSON entry try to parse it like it is done in 'cs_convert_falco_log_to_asff' and use it below for fields
       print (" DEBUG: EKS to ASFF parsed log LOG DATA type, contents: ", type(logEntry), logEntry )
       print ("---------------------------------------------")
       output = str(logEntry["output"])
       #severity = map_finding_severity(entry["log"]["priority"])
       severity = map_finding_severity(logEntry["priority"])
       print("DEBUG:  EKS to ASFF got output, severity:   ", output, severity)
    except:
       print("DEBUG: PROBLEM EKS to ASFF there's no 'output' or 'priority' entries in the Log above - cannot convert!")
       return None
      
    #check whether instance is null or not
    if instance is None:  
      #print("PROBLEM: Could not get instance_resource from NULL instance") 
      return None
    else:
      instance_resource = create_ec2_instance_resource(instance)
      print("DEBUG: EKS to ASFF got instance_resource: ", instance_resource)
      
    #eks_resources = get_eks_details(entry)
    #Use parsed JSON object to extract output_fields and more
    eks_resources = get_eks_details(logEntry)
    
    # Start building resources for ASFF message 
    resources = []
    resources.append(instance_resource)
    for container_resource in eks_resources:
        # print (" ========> DEBUG: adding EKS resource: ", container_resource)
        resources.append(container_resource)

    #Start forming ASFF message using known JSON format
    finding = {}
    finding["SchemaVersion"] = "2018-10-08"
    finding["AwsAccountId"] = account_id
    finding["Id"] = this_id
    #DZ: added for AB3
    finding["CompanyName"] = "AnyCompany"
    finding["Description"] = output
    finding["GeneratorId"] = instance_id + "-" + this_id.split("/")[-1]
    finding["ProductArn"] = f"arn:{PARTITION}:securityhub:{region}:{account_id}:product/{account_id}/default"
    finding["Severity"] = severity
    finding["Resources"] = resources
    #finding["Title"] = entry["log"]["rule"]
    finding["Title"] = logEntry["rule"]
    finding["Types"] = ["Container Software and Configuration Checks"]
    now = datetime.datetime.now()
    #Lambda is UTC time zone
    finding["UpdatedAt"] = f"{now.isoformat(timespec='milliseconds')}Z"
    finding["CreatedAt"] = f"{now.isoformat(timespec='milliseconds')}Z"

    # finally return the finding to the caller
    return finding

#Lambda handler function - entry point of CloudWatch event log processing logic 
def lambda_handler(event, context):
    cw_data = event['awslogs']['data']
    data_decoded = base64.b64decode(cw_data)
    data = json.loads(gzip.decompress(data_decoded).decode('utf-8'))
    
    findings = []
    #iterate through data['logEvents'], determine which ones are ECS cluster of EKS cluster related and process Falco logs
    #to form ASFF formatted security findings
    
    for entry in data['logEvents']:
        message = json.loads(entry['message'])
        #determine which app platform source of log message it is - ECS or EKS - and call corresponding function
        if "ecs_cluster" in message:
            # Add top level debug print
            print ("-------------------------------------------------------------")
            print ("LAMBDA FALCO DEBUG: BEFORE calling ECS_convert_falco_log_to_asff LOG Data type: ", type(message))
            print ("-------------------------------------------------------------")
            # end debug print
            finding = ecs_convert_falco_log_to_asff(message)
        #DZ: added condition for expected EKS cluster if "ec2_instance_type" field is present in Falco generated logs
        elif "ec2_instance_type" in message:
            # Add top level debug print
            print ("-------------------------------------------------------------")
            print ("LAMBDA FALCO DEBUG: BEFORE calling EKS_convert_falco_log_to_asff LOG entry Data type: ", type(message))
            print ("-------------------------------------------------------------")
            # end debug print
            finding = eks_convert_falco_log_to_asff(message)
        else:
            finding = None
            print ("LAMBDA FALCO PROBLEM ===>  Unknown CW Log event message type detected (not ECS, EKS) - DONT KNOW HOW TO PROCESS! <===")

        #after getting security findings, append it to an array
        #print ("RESULT: AFTER calling XXXX_convert_falco_log_to_asff ASFF finding is: ", finding)
        print ("-------------------------------------------------------------")
        
        #DZ: ignore 'empy' findings that may not be actual errors
        if finding is None:
           print("LAMBDA FALCO DEBUG: PROBLEM Cannot append EMPTY finding to 'findings' array")    
        else:    
           findings.append(finding)
           #print("LAMBDA FALCO DEBUG: OK Appended ASFF to findings: ", finding)
    #end for loop
    
    #batch import ASFF formatted findings into SecurityHub
    if len(findings) >0:
        sh = session.client('securityhub')
        # import findings to SecurityHUb via API call via Python
        r = sh.batch_import_findings(Findings=findings)
        print ("LAMBDA FALCO DEBUG: OK! Imported above ASFF findings into SecurityHub, response: ",r)
    else:
        print ("LAMBDA FALCO DEBUG: Could not Import EMPTY SECURITY findings into SecurityHub!")
        
    return

#DZ OPTIONAL new function to parse out in "log" field JSON substring to remove esscaped '\"'
def parseJSON(source): 

   #"log": "2023-02-02T00:43:56.734263328Z stdout F {\"hostname\":\"falco-z95gm\",\"output\":\"21:17:02.642052704: 
   # Error File below /etc opened for writing 
   # (user=<NA> user_loginuid=-1 command=touch /etc/26 pid=22583 parent=bash pcmdline=bash file=/etc/26 program=touch gparent=<NA> 
   # ggparent=<NA> gggparent=<NA>
   
   # print("DEBUG: INSIDE parseJSON the original string is: ", str(source))
   
   # res = source[idx1: idx2+2] # idx2+1 b/c we need the 2nd closing }}
   res = source.replace('\"','"')
   # printing result
   print("DEBUG: parseJSON - The extracted CLEAN LOG JSON Data type, values are: ", type(res), res)
   print ("--------------------------------------------")

   return res
