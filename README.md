## Custom integration for Falco security findings from Amazon Elastic Kubernetes Service (Amazon EKS)  into AWS Security Hub

The project deploys a Lambda function, that enables receiving Falco security findings from AWS CloudWatch logs, formatting them in ASFF JSON format and integrating into Security Hub

The `cdk.json` file instructs the CDK Toolkit how to execute your application. It was updated for CDK 2.0 per document: https://docs.aws.amazon.com/cdk/v2/guide/migrating-v2.html.

This project is set up like a standard Python project.  The initialization
process also creates a virtualenv within this project, stored under the `.venv`
directory.  To create the virtualenv it assumes that there is a `python3`
(or `python` for Windows) executable in your path with access to the `venv`
package. If for any reason the automatic creation of the virtualenv fails,
you can create the virtualenv manually.

To manually create a virtualenv on MacOS and Linux:

```
python3 -m venv .venv
```

After the init process completes and the virtualenv is created, you can use the following
steps to activate your virtualenv:

```
source .venv/bin/activate
```

If you are running the sample on a Windows platform, you would activate the virtualenv like this:

```
% .venv\Scripts\activate.bat
```

Once the virtualenv is activated, you can install the required dependencies.

```
python -m pip install -r requirements.txt
```

At this point you can now synthesize the CloudFormation template for this code.

```
cdk synth
```

To add additional dependencies, for example other CDK libraries, just add them to the `setup.py` file and rerun the `python -m pip install -r requirements.txt` command (or `pip install -r requirements.txt` from pip command prompt).

You may need to bootstrap your Account/region to cdk using command like:
```
cdk bootstrap aws://<account ID>/<us-west-2>
......
[WARNING] @aws-cdk/aws-lambda.Code#asset is deprecated.
  use `fromAsset`
  This API will be removed in the next major release.
 ⏳  Bootstrapping environment aws://<account ID>/us-west-2...
Trusted accounts for deployment: (none)
Trusted accounts for lookup: (none)
Using default execution policy of 'arn:aws:iam::aws:policy/AdministratorAccess'. Pass '--cloudformation-execution-policies' to customize.
CDKToolkit: creating CloudFormation changeset...
 ✅  Environment aws://<account ID>/us-west-2 bootstrapped.
```
Then initialize deployment of artifacts into target Account/Region environment:

```
cdk deploy
...
[WARNING] @aws-cdk/aws-lambda.Code#asset is deprecated.
  use `fromAsset`
  This API will be removed in the next major release.

✨  Synthesis time: 1.03s

This deployment will make potentially sensitive changes according to your current security approval level (--require-approval broadening).
Please confirm you intend to make the following modifications:

IAM Statement Changes
┌───┬───────────────────┬────────┬─────────────────────────────────┬──────────────────────────────┬───────────┐
│   │ Resource          │ Effect │ Action                          │ Principal                    │ Condition │
├───┼───────────────────┼────────┼─────────────────────────────────┼──────────────────────────────┼───────────┤
│ + │ ${CustomRole.Arn} │ Allow  │ sts:AssumeRole                  │ Service:lambda.amazonaws.com │           │
├───┼───────────────────┼────────┼─────────────────────────────────┼──────────────────────────────┼───────────┤
│ + │ *                 │ Allow  │ ec2:DescribeInstances           │ AWS:${CustomRole}            │           │
│ + │ *                 │ Allow  │ ecs:DescribeTasks               │ AWS:${CustomRole}            │           │
│ + │ *                 │ Allow  │ securityhub:BatchImportFindings │ AWS:${CustomRole}            │           │
└───┴───────────────────┴────────┴─────────────────────────────────┴──────────────────────────────┴───────────┘
IAM Policy Changes
┌───┬───────────────┬────────────────────────────────────────────────────────────────────────────────┐
│   │ Resource      │ Managed Policy ARN                                                             │
├───┼───────────────┼────────────────────────────────────────────────────────────────────────────────┤
│ + │ ${CustomRole} │ arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole │
└───┴───────────────┴────────────────────────────────────────────────────────────────────────────────┘
(NOTE: There may be security-related changes not in this list. See https://github.com/aws/aws-cdk/issues/1299)

Do you wish to deploy these changes (y/n)? y
AwsSecurityhubFalcoEksIntegrationStack: deploying... [1/1]
[0%] start: Building and publishing 23af06be3d08822fbfabb7584213fde595fd9086a8cce59bf34f1eaa43bd30ae:current
[100%] success: Built and published 23af06be3d08822fbfabb7584213fde595fd9086a8cce59bf34f1eaa43bd30ae:current
AwsSecurityhubFalcoEksIntegrationStack: creating CloudFormation changeset...

 ✅  AwsSecurityhubFalcoEksIntegrationStack

✨  Deployment time: 54.51s

Stack ARN:
arn:aws:cloudformation:us-west-2:133776528597:stack/AwsSecurityhubFalcoEksIntegrationStack/0630f0c0-961e-11ee-8bf5-06e93086ece7
✨  Total time: 55.54s
```
The message above should confirm successful deployment of AwsSecurityhubFalcoEksIntegrationStack components

## Useful CDK commands

 * `cdk ls`          list all stacks in the app
 * `cdk synth`       emits the synthesized CloudFormation template
 * `cdk deploy`      deploy this stack to your default AWS account/region
 * `cdk diff`        compare deployed stack with current state
 * `cdk docs`        open CDK documentation

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.

