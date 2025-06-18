package gatherProxyParsing

import (
	"regexp"
	"strings"
	"strconv"
	"fmt"
)

type Proxy struct {
	Ip           string
	Port         string
	Type         string
	Country      string
	ResponseTime int
}

var proxyListUri = "http://www.gatherproxy.com/proxylist/anonymity/"
var typeParam = "Type"
var indexParam = "PageIdx"
var uptimeParam = "Uptime"

func getCountOfPage(text string) int {
	text = strings.Replace(text, "\n", " ", -1)

	divRegex := regexp.MustCompile("<div class=\"pagenavi\">(.*?)</div>")
	nodes := divRegex.FindAllStringSubmatch(text, -1)

	var cnt int
	cnt = 0

	if nodes != nil {
		for _, node := range nodes {
			var div = node[1]

			linkRegex := regexp.MustCompile("<a .*?>(.*?)</a>")
			linkNodes := linkRegex.FindAllStringSubmatch(div, -1)

			if linkNodes != nil {
				for _, linkNode := range linkNodes {
					var link = linkNode[1]

					num, _ := strconv.Atoi(link)
					cnt = num
				}
			}
		}
	}

	return cnt
}

func parseGatherProxy(text string) []Proxy {
	var proxies []Proxy

	text = strings.Replace(text, "\n", " ", -1)
	trRegex := regexp.MustCompile("<td>(.*?)</td>\\s*<td><script>document.write\\('(.*?)'\\)\\s*</script></td>\\s*<td><script>document.write\\(gp.dep\\('(.*?)'\\)\\)\\s*</script></td>\\s*<td .*?>(.*?)</td>\\s*<td>(.*?)</td>\\s*<td></td>\\s*<td .*?>(.*?)</td>\\s*<td .*?>(.*?)</td>")
	nodes := trRegex.FindAllStringSubmatch(text, -1)

	if nodes != nil {
		for _, node := range nodes {
			port, _ := strconv.ParseInt(node[3], 16, 0)

			var time = strings.Replace(node[7], "ms", "", -1)
			numTime, _ := strconv.Atoi(time)

			var proxy Proxy
			proxy.Ip = node[2]
			proxy.Port = fmt.Sprint(port)
			proxy.Type = node[4]
			proxy.Country = node[5]
			proxy.ResponseTime = numTime

			proxies = append(proxies, proxy)
		}
	}

	return proxies
}

func proxyInSlice(proxy Proxy, list []Proxy) bool {
	for _, p := range list {
		if p.Ip == proxy.Ip {
			return true
		}
	}
	return false
}
