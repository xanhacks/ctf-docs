---
title: Go
description: Golang example of code snippets.
---

# Golang practical example

## Make an HTTP request

### GET

Source (main.go) :

```go
package main

import (
    "io/ioutil"
    "log"
    "net/http"
    "flag"
)

func getRequest(url string) (string, error) {
    resp, err := http.Get(url)

    if err != nil {
        return "", err
    }

    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)

    if err != nil {
        return "", err
    }

    return string(body), nil
}


func main() {
    var url string
    flag.StringVar(&url, "url", "https://example.com", "URL to request")
    flag.Parse()

    response, err := getRequest(url)

    if err != nil {
        log.Fatalln(err)
    }

    log.Printf(response)
}
```

Execution :

```bash
$ python3 -m http.server &
$ go run main.go -url 'http://localhost:8000'
2021/11/08 18:41:02 <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
...
```

## Cryptography

### md5

Source (main.go) :

```go
package main

import (
    "crypto/md5"
    "fmt"
)

func main() {
    buffer := []byte("helloworld")

    fmt.Printf("%x", md5.Sum(buffer))
}
```

Execution :

```bash
$ go run main.go
fc5e038d38a57032085441e7fe7010b0
```

### Rainbow tables of rockyou (md5)

Source (main.go) :

```go
package main

import (
    "crypto/md5"
    "fmt"
    "bufio"
    "log"
    "os"
)

func main() {
    wordlist, err := os.Open("/opt/rockyou.txt")
    if err != nil {
        log.Fatal(err)
    }

    defer wordlist.Close()

    output, err := os.Create("rockyou.txt.md5")
    if err != nil {
        log.Fatal(err)
    }

    defer output.Close()

    scanner := bufio.NewScanner(wordlist)
    for scanner.Scan() {
        data := []byte(scanner.Text())
        hash := fmt.Sprintf("%x\n", md5.Sum(data))
        output.WriteString(hash)
    }

    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }
}
```

Execution :

```bash
$ go run main.go

# Checking first line
$ cat /opt/rockyou.txt | head -n1 | tr -d '\n' | md5sum ; cat rockyou.txt.md5 | head -n1
e10adc3949ba59abbe56e057f20f883e  -
e10adc3949ba59abbe56e057f20f883e
```

### Crack sha512-salt password

Source code :

```go
package main

import (
    "crypto/sha512"
    "fmt"
    "bufio"
    "log"
    "os"
)

func hashPassword(password string, salt string) string {
    hash := sha512.Sum512([]byte(password + salt))
    return fmt.Sprintf("%x", hash)
}

func verifyPass(hash, salt, password string) bool {
    resultHash := hashPassword(password, salt)
    return resultHash == hash
}

func main() {
    hash := "6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed"
    salt := "1c362db832f3f864c8c2fe05f2002a05"

    wordlist, err := os.Open("/opt/rockyou.txt")
    if err != nil {
        log.Fatal(err)
    }

    defer wordlist.Close()

    scanner := bufio.NewScanner(wordlist)
    for scanner.Scan() {
        line := scanner.Text()
        if verifyPass(hash, salt, line) {
            fmt.Println(line)
            break;
        }
    }
}
```

Execution :

```bash
$ go run cracker.go
november16
```
