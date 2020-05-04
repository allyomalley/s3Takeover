## About

Tool to automate the process of an S3 bucket takeover via CNAME - given a target domain name, it will attempt to verify the vulnerability, and extract the targetted bucket name and region from the domain's CNAME record.

## Installation

Install the tool and required dependencies:

```
go get github.com/allyomalley/s3Takeover/...
```

## Usage

```
go run s3Takeover.go <Target URL>
```
