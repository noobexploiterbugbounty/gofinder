package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

var transport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: time.Second,
		DualStack: true,
	}).DialContext,
}

var httpClient = &http.Client{
	Transport: transport,
}
var regexes = map[string]string{
	"slack_token":                   "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
	"slack_webhook":                 "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
	"facebook_oauth":                "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
	"twitter_oauth":                 "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
	"twitter_access_token":          "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
	"heroku_api":                    "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
	"mailgun_api":                   "key-[0-9a-zA-Z]{32}",
	"mailchamp_api":                 "[0-9a-f]{32}-us[0-9]{1,2}",
	"picatic_api":                   "sk_live_[0-9a-z]{32}",
	"google_oauth_id":               "[0-9(+-[0-9A-Za-z_]{32}.apps.googleusercontent.com",
	"google_api":                    "AIza[0-9A-Za-z-_]{35}",
	"google_oauth":                  "ya29\\.[0-9A-Za-z\\-_]+",
	"amazon_aws_access_key_id":      "AKIA[0-9A-Z]{16}",
	"amazon_mws_auth_token":         "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
	"amazonaws_url":                 "s3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com",
	"facebook_access_token":         "EAACEdEose0cBA[0-9A-Za-z]+",
	"mailgun_api_key":               "key-[0-9a-zA-Z]{32}",
	"paypal_braintree_access_token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
	"square_oauth_secret":           "sq0csp-[ 0-9A-Za-z\\-_]{43}",
	"square_access_token":           "sqOatp-[0-9A-Za-z\\-_]{22}",
	"stripe_standard_api":           "sk_live_[0-9a-zA-Z]{24}",
	"stripe_restricted_api":         "rk_live_[0-9a-zA-Z]{24}",
	"github_access_token":           "[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*",
	"private_ssh_key":               "-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END PRIVATE KEY-----",
	"private_rsa_key":               "-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END RSA PRIVATE KEY-----",
	"gpg_private_key_block":         "-----BEGIN PGP PRIVATE KEY BLOCK-----",
	"generic_api_key":               "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
	"generic_secret":                "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
	"password_in_url":               "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
}

func main() {
	//Init variables
	urls := make(chan string)
	var wg sync.WaitGroup
	var threads int
	flag.IntVar(&threads, "t", 20, "Specify number of threads to run")
	flag.Parse()

	//Setup Workers
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go workers(urls, &wg)
	}

	//Get input
	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		urls <- input.Text()
	}
	close(urls)

	//Wait till everything is done
	wg.Wait()
}

func findregex(s string) {
	resp, err := httpClient.Get(s)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	for a, b := range regexes {
		r, _ := regexp.Compile(b)
		found := r.FindAllString(string(body), -1)
		if len(found) != 0 {
			for _, i := range found {
				fmt.Printf("[%s] %s %s\n", a, i, s)
			}
		}
	}
}

func workers(cha chan string, wg *sync.WaitGroup) {
	for i := range cha {
		findregex(i)
	}
	wg.Done()
}
