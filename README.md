# gossh

Golang ssh library, support file upload and download.

## Example
```go
package main

import (
    "github.com/iswarezwp/gossh"
    "log"
)

// returns a function of type gossh.Writer func(...interface{})
// MakeLogger just adds a prefix (DEBUG, INFO, ERROR)
func MakeLogger(prefix string) gossh.Writer {
    return func(args ...interface{}) {
        log.Println((append([]interface{}{prefix}, args...))...)
    }
}

func main() {
    client := gossh.New("192.168.1.127", "root")
    client.SetPassword("isware")
    client.DebugWriter = MakeLogger("DEBUG")
    client.InfoWriter = MakeLogger("INFO ")
    client.ErrorWriter = MakeLogger("ERROR")

    defer client.Close()

    var e error
    for {
        if _, e = client.Execute("uptime"); e != nil {
            break
        }

        if _, e = client.Execute("echo -n $(cat /proc/loadavg); cat /does/not/exists"); e != nil {
            break
        }

        if _, e = client.Get("/opt/go/web.go", "download"); e != nil {
            break
        }

        if _, e = client.Put("download1", "/opt/tttttt.go"); e != nil {
            break
        }

        break
    }

    if e != nil {
        client.ErrorWriter(e.Error())
    }
}
```

## Tunnelling HTTP Connections
For services not bound to the public interface of a machine, tunnelling is a quite nice SSH feature. It allows to use a
remote service like it is running at the local machine. This concept is used in the HTTP client returned by the
NewHttpClient function. It is a common net/http.Client, but all requests are sent through the SSH connection given.
