## About

Tool to automate the process of an S3 bucket takeover via CNAME - given a target domain name, it will attempt to verify the vulnerability, extract the targetted bucket name and region from the domain's CNAME record, and then create the S3 bucket. 

## Installation

Install the tool and required dependencies:

```
go get github.com/allyomalley/s3Takeover/...
```

Note that the bucket creation process uses the AWS SDK for Go - it will automatically use the credentials you have configured with the AWS CLI.

## Usage

```
go run s3Takeover.go <Target URL>
```
