# GatherProxy Parser

[![GoDoc](https://godoc.org/github.com/veksa/gather-proxy-parsing?status.svg)](https://godoc.org/github.com/veksa/gather-proxy-parsing)  

Parse the GatherProxy proxies website with GO

## Usage ##

Get the package:

```shell
go get github.com/veksa/gather-proxy-parsing
```

Import him into your code:

```go
import "github.com/veksa/gather-proxy-parsing"
```

Get list of proxies and test it. For example:

```go
proxies := gatherProxyParsing.GetProxies("Elite", 0)

// first parameter is proxyType - one of Transparent, Elite or Anonymous
// second parameter is filter by uptime

successCallback := func(proxy Proxy) { activateProxy(proxy) }
errorCallback := func(proxy Proxy) { deactivateProxy(proxy) }

gatherProxyParsing.TestProxies(proxies, successCallback, errorCallback)
```