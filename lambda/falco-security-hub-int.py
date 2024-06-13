import json
import boto3
import uuid
import datetime
import base64
import gzip
import logging

PARTITION="aws"

session = boto3.session.Session()
ec2 = session.resource("ec2")
sts = session.client('sts')
#ecs = session.client('ecs')

#Get EC2 instance by its ID
def get_ec2_details(instance_id):
        instance = ec2.Instance(instance_id)
        #print("get_ec2_details got instance: ",instance)
        return instance
    
#Get account ID 
def get_account_id():

    caller = sts.get_caller_identity()
    return caller.get("Account")


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
    

# Retrieve details of EKS Falco log message entry obtained from 'ouput_fields element'

def get_eks_details(message):
   
    fields = None
    try: 
       #fields = log["output_fields"]
       fields = message["output_fields"]
       logging.debug ("DEBUG: 'get EKS details' log 'output_fields' values are: ", fields)
       
    except:
       logging.error("PROBLEM: 'get EKS details' - there's no log element for 'output_fields'?!")
      
    finally:
       #print("CHECK: get_eks_details got output_fields: ", fields)  
       logging.info("")
    
    #Initialize container metadata to placeholder parameters
    container_id = "test"
    pod_name = "test"
    namespace = "test"
    image = "test"
    
    # output = str(logEntry["output"])
    #check if fields elements has values   
    if fields is None:
       logging.critical("CRITICAL PROBLEM in get_eks_details - no data for 'output_fields', cannot retrieve details!!! ")    
    else:    
       try:
          container_id = fields["container.id"]
          pod_name = fields["k8s.pod.name"]
          namespace = fields["k8s.ns.name"]
          #container.image.repository
          image = str(fields["container.image.repository"])
       except:
          logging.error("PROBLEM: get EKS details - looks like there are no EXPECTED 'container' element in 'output_fields' block!")
       finally:
          logging.debug ("DEBUG: get EKS details obtained Container details: container_id, pod_name, namespace, image: ", container_id, pod_name, namespace, image) 
          logging.info ("-------------------------------------------------------------------------")
          
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


# Convert EKS Falco log message to AWS ASFF format for SecurityHub import
def eks_convert_falco_log_to_asff(entry):
    region = session.region_name
    
    # intialize instance variables
    instance_id = None
    instance = None
    # Starting try-catch block
    try: 
      instance_id = entry["ec2_instance_id"]
      instance = get_ec2_details(instance_id)
      logging.info("EKS to ASFF DEBUG: got instance_id, instance: ",instance_id,instance)
    except:
      logging.error("EKS to ASFF PROBLEM: looks like there's no element for 'ec2_instance_id'")
   
    finally:
      #print("EKS to ASFF got ec2_instance: ", instance)
      logging.info("")
    # ending try-catch block
    
    #get AWDS account ID
    account_id= get_account_id()
    
    #generate ID for this object
    this_id = generate_id(account_id,region)
    # print ("EKS to ASFF got account ID, this_id ", account_id, this_id)
    
    # Initialize log Entry 
    logEntry = None
    try: 
       #output = entry["log"]["output"]
       logEntry = json.loads(entry["log"])
       # after getting clean JSON entry try to parse it like it is done in 'cs_convert_falco_log_to_asff' and use it below for fields
       logging.debug (" DEBUG: EKS to ASFF parsed log LOG DATA type, contents: ", type(logEntry), logEntry )
       logging.info ("-------------------------------------------------------------------------------------")
       output = str(logEntry["output"])
       #severity = map_finding_severity(entry["log"]["priority"])
       severity = map_finding_severity(logEntry["priority"])
       #print("DEBUG: EKS to ASFF got Event output, severity:   ", output, severity)
    except:
       logging.error("PROBLEM EKS to ASFF there's no 'output' or 'priority' entries in the Log above - cannot convert!")
       return None
      
    #check whether instance is null or not
    if instance is None:  
      logging.error("PROBLEM: Could not get instance_resource from NULL instance") 
      return None
    else:
      instance_resource = create_ec2_instance_resource(instance)
      logging.debug("EKS to ASFF: got instance_resource: ", instance_resource)
      
    #eks_resources = get_eks_details(entry)
    #Use parsed JSON object to extract output_fields and more
    eks_resources = get_eks_details(logEntry)
    
    # Start building resources for ASFF message 
    resources = []
    resources.append(instance_resource)
    for container_resource in eks_resources:
        resources.append(container_resource)

    #Start forming ASFF message using known JSON format
    finding = {}
    finding["SchemaVersion"] = "2018-10-08"
    finding["AwsAccountId"] = account_id
    finding["Id"] = this_id
    #Added for distinction of ASFF records fro demo purposes, please change to your Company name
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

    # return the ASFF formatted finding to the caller
    return finding

#Lambda handler function - entry point of CloudWatch event log processing logic 
def lambda_handler(event, context):
    cw_data = event['awslogs']['data']
    data_decoded = base64.b64decode(cw_data)
    data = json.loads(gzip.decompress(data_decoded).decode('utf-8'))
    
    findings = []
    #iterate through data['logEvents'], determine which ones are EKS cluster related and process Falco logs
    #to form ASFF formatted security findings messages
    
    for entry in data['logEvents']:
        message = json.loads(entry['message'])
        # Determine which container platform is a source of log message (only EKS is actually sdupported) and call corresponding function
        # unlikely to be used with ECS source - kept only for backward compatibility
        if "ecs_cluster" in message:
            # Add top level debug logging
            #logging.debug ("-------------------------------------------------------------")
            logging.warning ("LAMBDA FALCO WARN: ECS LOG Entry Data type processing is NOT supported: ", type(message))
            logging.info ("-------------------------------------------------------------")
            # end debug logging
            # finding = ecs_convert_falco_log_to_asff(message)
            
        #Added condition for expected EKS cluster source: if "ec2_instance_type" field is present in Falco generated logs
        elif "ec2_instance_type" in message:
            # Add top level debug logging
            #logging.info ("-------------------------------------------------------------")
            logging.debug ("LAMBDA FALCO DEBUG: BEFORE calling EKS_convert_falco_log LOG entry Data type: ", type(message))
            logging.info ("-------------------------------------------------------------")
            # end debug logging
            finding = eks_convert_falco_log_to_asff(message)
        else:
            finding = None
            logging.warning ("LAMBDA FALCO event handler: Unknown CW Log event message source detected - cannot determine security finding!")

        #after getting security findings, append it to an array
        logging.debug ("LAMBDA FALCO DEBUG: AFTER calling XXXX_convert_falco_log_to_asff ASFF finding is: ", finding)
        #logging.info ("-------------------------------------------------------------")
        
        #ignore 'empty' findings that may not be actual errors
        if finding is None:
           logging.warning("LAMBDA FALCO: PROBLEM Cannot append EMPTY finding to 'findings' for SecurityHub")    
        else:    
           findings.append(finding)
           logging.debug("LAMBDA FALCO: Sucessfully Appended ASFF data to findings: ", finding)
    #end for loop
    
    #batch import ASFF formatted findings into SecurityHub
    if len(findings) >0:
        # open API session to SecurityHub
        sh = session.client('securityhub')
        # import findings to SecurityHUb via API call with Python
        r = sh.batch_import_findings(Findings=findings)
        logging.info ("LAMBDA FALCO - SUCCESS: Imported ASFF findings above into Regional SecurityHub, response: ",r)
    else:
        logging.warning ("LAMBDA FALCO - PROBLEM: Could not Import EMPTY SECURITY findings into SecurityHub!")
        
    return

# OPTIONAL new function to parse out in "log" field JSON substring to remove esscaped '\"'
def parseJSON(source): 

   res = source.replace('\"','"')
   # printing result
   logging.warning("DEBUG: parseJSON - The extracted CLEAN LOG JSON Data type, values are: ", type(res), res)
   logging.info ("--------------------------------------------------------------------------")

   return res
