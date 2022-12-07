## About

Tool to automate the process of an S3 bucket takeover via CNAME - given a target domain name, it will attempt to verify the vulnerability, extract the targetted bucket name and region from the domain's CNAME record, and then create the S3 bucket in your AWS account. 

## Installation

Install the tool and required dependencies:

```
go install github.com/allyomalley/s3Takeover@latest
```

Note that the bucket creation process uses the AWS SDK for Go - it will automatically use the credentials you have configured with the AWS CLI.

## Usage

```
s3Takeover <Target URL>
```
