package gossh

import (
    "bytes"
    "compress/gzip"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "time"

    "code.google.com/p/go.crypto/ssh"
    "code.google.com/p/go.crypto/ssh/agent"
    "github.com/iswarezwp/sftp"
)

func New(host, user string) (c *Client) {
    return &Client{
        User: user,
        Host: host,
    }
}

type Client struct {
    User        string
    Host        string
    Port        int
    Agent       net.Conn
    password    string
    Conn        *ssh.Client
    SftpClient  *sftp.Client
    DebugWriter Writer
    ErrorWriter Writer
    InfoWriter  Writer
}

func (c *Client) Password(user string) (password string, e error) {
    if c.password != "" {
        return c.password, nil
    }
    return "", fmt.Errorf("password must be set with SetPassword()")
}

func (c *Client) Close() {
    if c.SftpClient != nil {
        c.SftpClient.Close()
    }
    if c.Conn != nil {
        c.Conn.Close()
    }
    if c.Agent != nil {
        c.Agent.Close()
    }
}

func (client *Client) Attach() error {
    options := []string{"-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no"}
    if client.User != "" {
        options = append(options, "-l", client.User)
    }
    options = append(options, client.Host)
    log.Printf("executing %#v", options)
    cmd := exec.Command("/usr/bin/ssh", options...)
    cmd.Stderr = os.Stderr
    cmd.Stdout = os.Stdout
    cmd.Stdin = os.Stdin
    cmd.Env = os.Environ()
    return cmd.Run()
}

func (c *Client) SetPassword(password string) {
    c.password = password
}

func (c *Client) Connection() (*ssh.Client, error) {
    if c.Conn != nil {
        return c.Conn, nil
    }
    e := c.Connect()
    if e != nil {
        return nil, e
    }
    return c.Conn, nil
}

func (c *Client) ConnectWhenNotConnected() (e error) {
    if c.Conn != nil {
        return nil
    }
    return c.Connect()
}

func (c *Client) Connect() (e error) {
    if c.Port == 0 {
        c.Port = 22
    }

    var auths []ssh.AuthMethod
    if c.password != "" {
        auths = append(auths, ssh.Password(c.password))
    } else if c.Agent, e = net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); e == nil {
        auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(c.Agent).Signers))
    }

    config := &ssh.ClientConfig{
        User: c.User,
        Auth: auths,
    }
    c.Conn, e = ssh.Dial("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port), config)
    if e != nil {
        return e
    }

    c.SftpClient, e = sftp.NewClient(c.Conn)
    return e
}

func (c *Client) Execute(s string) (r *Result, e error) {
    started := time.Now()
    if e = c.ConnectWhenNotConnected(); e != nil {
        return nil, e
    }
    ses, e := c.Conn.NewSession()
    if e != nil {
        return nil, e
    }
    defer ses.Close()

    tmodes := ssh.TerminalModes{
        53:  0,     // disable echoing
        128: 14400, // input speed = 14.4kbaud
        129: 14400, // output speed = 14.4kbaud
    }

    if e := ses.RequestPty("xterm", 80, 40, tmodes); e != nil {
        return nil, e
    }

    r = &Result{
        StdoutBuffer: &LogWriter{LogTo: c.Debug},
        StderrBuffer: &LogWriter{LogTo: c.Error},
    }

    ses.Stdout = r.StdoutBuffer
    ses.Stderr = r.StderrBuffer
    c.Info(fmt.Sprintf("[EXEC] %s", s))
    r.Error = ses.Run(s)
    c.Info(fmt.Sprintf("=> %.06f", time.Now().Sub(started).Seconds()))
    if exitError, ok := r.Error.(*ssh.ExitError); ok {
        r.ExitStatus = exitError.ExitStatus()
    }
    r.Runtime = time.Now().Sub(started)
    if !r.Success() {
        r.Error = fmt.Errorf("process exited with %d", r.ExitStatus)
    }
    return r, r.Error
}

func (c *Client) Put(localfile, remotefile string) (r *Result, e error) {
    c.Info(fmt.Sprintf("upload file `%s` to `%s`", localfile, remotefile))

    started := time.Now()
    if e = c.ConnectWhenNotConnected(); e != nil {
        return nil, e
    }

    flocal, e := os.Open(localfile)
    if e != nil {
        return nil, e
    }
    defer flocal.Close()

    fremote, e := c.SftpClient.Create(remotefile)
    if e != nil {
        return nil, e
    }
    defer fremote.Close()

    if _, e := io.Copy(fremote, flocal); e != nil {
        return nil, e
    }
    c.Info(fmt.Sprintf("=> %.06f", time.Now().Sub(started).Seconds()))

    return nil, nil
}

func (c *Client) Get(remotefile, localfile string) (r *Result, e error) {
    c.Info(fmt.Sprintf("download file `%s` to `%s`", remotefile, localfile))

    started := time.Now()
    if e = c.ConnectWhenNotConnected(); e != nil {
        return nil, e
    }

    fremote, e := c.SftpClient.Open(remotefile)
    if e != nil {
        return nil, e
    }
    defer fremote.Close()

    flocal, e := os.Create(localfile)
    if e != nil {
        return nil, e
    }
    defer flocal.Close()

    if _, e := io.Copy(flocal, fremote); e != nil {
        return nil, e
    }
    c.Info(fmt.Sprintf("=> %.06f", time.Now().Sub(started).Seconds()))

    return nil, nil
}

func (c *Client) Debug(args ...interface{}) {
    c.Write(c.DebugWriter, args)
}

func (c *Client) Error(args ...interface{}) {
    c.Write(c.ErrorWriter, args)
}

func (c *Client) Info(args ...interface{}) {
    c.Write(c.InfoWriter, args)
}

var b64 = base64.StdEncoding

func (c *Client) WriteFile(path, content, owner string, mode int) (res *Result, e error) {
    return c.Execute(c.WriteFileCommand(path, content, owner, mode))
}

func (c *Client) WriteFileCommand(path, content, owner string, mode int) string {
    buf := &bytes.Buffer{}
    zipper := gzip.NewWriter(buf)
    zipper.Write([]byte(content))
    zipper.Flush()
    zipper.Close()
    encoded := b64.EncodeToString(buf.Bytes())
    hash := sha256.New()
    hash.Write([]byte(content))
    checksum := fmt.Sprintf("%x", hash.Sum(nil))
    tmpPath := "/tmp/gossh." + checksum
    dir := filepath.Dir(path)
    cmd := fmt.Sprintf("sudo mkdir -p %s && echo %s | base64 -d | gunzip | sudo tee %s", dir, encoded, tmpPath)
    if owner != "" {
        cmd += " && sudo chown " + owner + " " + tmpPath
    }
    if mode > 0 {
        cmd += fmt.Sprintf(" && sudo chmod %o %s", mode, tmpPath)
    }
    cmd = cmd + " && sudo mv " + tmpPath + " " + path
    return cmd
}

func (c *Client) Write(writer Writer, args []interface{}) {
    if writer != nil {
        writer(args...)
    }
}

// Returns an HTTP client that sends all requests through the SSH connection (aka tunnelling).
func NewHttpClient(sshClient *Client) (httpClient *http.Client, e error) {
    if e = sshClient.ConnectWhenNotConnected(); e != nil {
        return nil, e
    }
    httpClient = &http.Client{}
    httpClient.Transport = &http.Transport{Proxy: http.ProxyFromEnvironment, Dial: sshClient.Conn.Dial}
    return httpClient, nil
}
