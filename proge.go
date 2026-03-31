package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const baseDomain = "ba.tilhempel.info"
const randMax = 100000

func domainAssembly(dnsServer string, tokenDepth int) string {
	octets := strings.Split(dnsServer, ".")
	if len(octets) != 4 {
		log.Fatalln("Please provide an correct IPv4 Adress: ", dnsServer)
	}

	var idToken = ""

	for _, oc := range octets {
		ocInt, err := strconv.Atoi(oc)
		if err != nil {
			log.Fatalln("Please provide an correct IPv4 Adress: ", dnsServer)
		}
		if ocInt < 16 {
			idToken += "0"
		}
		idToken += strconv.FormatInt(int64(ocInt), 16)
	}

	idToken += strconv.Itoa(tokenDepth)
	idToken += strconv.Itoa(rand.Intn(randMax))

	var domain = ""

	for i := tokenDepth - 1; i > 0; i-- {
		domain += strconv.Itoa(i) + "."
	}

	domain += idToken + "." + baseDomain
	return domain
}
func dnsQuery(domain string, server string, qType uint16) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qType)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Net = "udp"
	res, _, err := c.Exchange(m, server+":53")
	if err != nil {
		return nil, fmt.Errorf("Querry failed: %v", err)
	}

	if res.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("query error: %s", dns.RcodeToString[res.Rcode])
	}
	var results []string
	for _, ans := range res.Answer {
		switch qType {
		case dns.TypeA:
			if a, ok := ans.(*dns.A); ok {
				results = append(results, a.A.String())
			}
		case dns.TypeAAAA:
			if aaaa, ok := ans.(*dns.AAAA); ok {
				results = append(results, aaaa.AAAA.String())
			}
		case dns.TypeTXT:
			if txt, ok := ans.(*dns.TXT); ok {
				results = append(results, txt.Txt...)
			}
		}
	}
	return results, nil

}

func dnsQueryRoutine(tokenDepth int, server string, qType uint16, ch chan<- []string, wg *sync.WaitGroup) interface{} {
	defer wg.Done()
	res, err := dnsQuery(domainAssembly(server, tokenDepth), server, qType)
	if err != nil {
		fmt.Println("A record error:", err)
		return err
	}
	ch <- res
	return res
}

func scanResolvers(resolver []string) map[string][]string {
	var out = make(map[string][]string)

	for _, ip := range resolver {
		fmt.Println("Probing Server: ", ip)
		ch := make(chan []string)
		var wg sync.WaitGroup

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go dnsQueryRoutine(24, ip, dns.TypeTXT, ch, &wg)
			time.Sleep(time.Duration(time.Duration.Milliseconds(10)))
		}

		go func() {
			wg.Wait()
			close(ch)
		}()

		out[ip] = <-ch
	}
	return out
}

type kvPair struct {
	Key   string
	value int
}

func evalRsults(raw map[string][]string) map[string][3]string {
	var out = make(map[string][3]string)
	for k, v := range raw {
		qmin := -1
		var counter = make(map[string]int)
		mostFreq := kvPair{"", 0}

		for _, seq := range v {

			if strings.Contains(seq, "|") {
				switch qmin {
				case 0:
					qmin = 2
				case -1:
					qmin = 1
				}
				seq = seq[:strings.LastIndex(seq, "|")+1]
			} else {
				switch qmin {
				case 1:
					qmin = 2
				case -1:
					qmin = 0
				}
				seq = seq[:strings.LastIndex(seq, ".")+1]
			}
			seq += "*idToken*"
			if val, ok := counter[seq]; ok {
				counter[seq] = val + 1
			} else {
				counter[seq] = 1
			}
			if counter[seq] > mostFreq.value {
				mostFreq = kvPair{seq, counter[seq]}
			}
		}
		out[k] = [3]string{
			strconv.Itoa(qmin),
			mostFreq.Key,
			strconv.Itoa(mostFreq.value),
		}
	}
	return out
}

func writeOutputCSV(data map[string][3]string) {
	var csvData = [][]string{}

	for k, v := range data {
		csvData = append(csvData, []string{k, v[0], v[1]})
	}

	file, err := os.Create(("./out.csv"))
	if err != nil {
		log.Fatalln("Couldn't create output file: ", err.Error())
	}
	writer := csv.NewWriter(file)
	err = writer.WriteAll(csvData)

	if err != nil {
		log.Fatalln("Couldn't write to Output File: ", err.Error())
	}
}

func readCSV(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalln("Couldn't open CSV file: ", err.Error())
	}
	reader := csv.NewReader(file)
	records, _ := reader.ReadAll()

	var ips = []string{}
	for _, record := range records[1:] {
		ips = append(ips, record[1])
	}
	return ips
}

func main() {
	start := time.Now()
	server := readCSV("/home/Til/Downloads/apidownload/data/odns_udp_2026-03-31.csv")
	server = server[100:115]

	results := scanResolvers(server)
	writeOutputCSV(evalRsults(results))
	fmt.Println("runtime: ", time.Since(start))

}
