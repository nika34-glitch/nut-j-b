package gatherProxyParsing

// proxyType is one of Transparent, Elite or Anonymous
func GetProxies(proxyType string, minUptime uint32) []Proxy {
    var proxies []Proxy

    // get count of page
    text, _ := getPage(proxyListUri, proxyType, 1, minUptime)
    pageCount := getCountOfPage(string(text))
    for i := 1; i <= pageCount; i++ {
        text, _ := getPage(proxyListUri, proxyType, i, minUptime)
        proxies = append(proxies, parseGatherProxy(string(text))...)
    }

    var cleanedProxies []Proxy
    for _, value := range proxies {
        if !proxyInSlice(value, cleanedProxies) {
            cleanedProxies = append(cleanedProxies, value)
        }
    }

    return cleanedProxies
}

type successCallback func(Proxy)
type errorCallback func(Proxy)

func TestProxies(proxies []Proxy, successFn successCallback, errorFn errorCallback) {
    for _, proxy := range proxies {
        check, _ := testPage("http://google.ru", proxy, "<title>Google</title>")
        if check {
            successFn(proxy)
        } else {
            errorFn(proxy)
        }
    }
}