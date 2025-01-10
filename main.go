package main

import (
    "bufio"
    "flag"
    "fmt"
    "golang.org/x/crypto/ssh"
    "io/ioutil"
    "os"
    "path/filepath"
    "strings"
    "time"
)

type KnownHost struct {
    Hostname    string
    KeyType     string
    PublicKey   string
    RawEntry    string
}

type SSHConfig struct {
    Username string
    Password string
    KeyPath  string
    Port     int
}

func trySSHLogin(host string, config SSHConfig) error {
    var authMethods []ssh.AuthMethod
    
    // Try key-based auth if key path is provided
    if config.KeyPath != "" {
        key, err := ioutil.ReadFile(config.KeyPath)
        if err == nil {
            signer, err := ssh.ParsePrivateKey(key)
            if err == nil {
                authMethods = append(authMethods, ssh.PublicKeys(signer))
            }
        }
    }
    
    // Add password auth if password is provided
    if config.Password != "" {
        authMethods = append(authMethods, ssh.Password(config.Password))
    }
    
    if len(authMethods) == 0 {
        return fmt.Errorf("no valid authentication methods available")
    }

    sshConfig := &ssh.ClientConfig{
        User: config.Username,
        Auth: authMethods,
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
        Timeout: 10 * time.Second,
    }

    // Try to connect
    hostWithPort := fmt.Sprintf("%s:%d", host, config.Port)
    client, err := ssh.Dial("tcp", hostWithPort, sshConfig)
    if err != nil {
        return fmt.Errorf("failed to connect: %v", err)
    }
    defer client.Close()

    // Try to create a session (validates the connection)
    session, err := client.NewSession()
    if err != nil {
        return fmt.Errorf("failed to create session: %v", err)
    }
    defer session.Close()

    return nil
}

func parseKnownHostsFile(path string) ([]KnownHost, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, fmt.Errorf("failed to open file %s: %v", path, err)
    }
    defer file.Close()

    var hosts []KnownHost
    scanner := bufio.NewScanner(file)
    
    for scanner.Scan() {
        line := scanner.Text()
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }

        parts := strings.SplitN(line, " ", 3)
        if len(parts) != 3 {
            continue
        }

        host := KnownHost{
            Hostname:    parts[0],
            KeyType:     parts[1],
            PublicKey:   parts[2],
            RawEntry:    line,
        }
        hosts = append(hosts, host)
    }

    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("error reading file %s: %v", path, err)
    }

    return hosts, nil
}

func getAllKnownHosts(sshDir string) ([]KnownHost, error) {
    var allHosts []KnownHost
    var parseErrors []string
    
    // Try to parse known_hosts
    knownHostsPath := filepath.Join(sshDir, "known_hosts")
    hosts, err := parseKnownHostsFile(knownHostsPath)
    if err != nil {
        parseErrors = append(parseErrors, fmt.Sprintf("known_hosts: %v", err))
    } else {
        allHosts = append(allHosts, hosts...)
        fmt.Printf("Successfully parsed %s (%d entries)\n", knownHostsPath, len(hosts))
    }

    // Try to parse known_hosts.old if it exists
    oldHostsPath := filepath.Join(sshDir, "known_hosts.old")
    oldHosts, err := parseKnownHostsFile(oldHostsPath)
    if err != nil {
        parseErrors = append(parseErrors, fmt.Sprintf("known_hosts.old: %v", err))
    } else {
        allHosts = append(allHosts, oldHosts...)
        fmt.Printf("Successfully parsed %s (%d entries)\n", oldHostsPath, len(oldHosts))
    }

    if len(allHosts) == 0 {
        return nil, fmt.Errorf("failed to parse any hosts files:\n%s", strings.Join(parseErrors, "\n"))
    }

    return allHosts, nil
}

func main() {
    // Parse command line flags
    username := flag.String("user", "", "SSH username")
    password := flag.String("password", "", "SSH password (optional if using key)")
    keyPath := flag.String("key", "", "Path to SSH private key (optional if using password)")
    port := flag.Int("port", 22, "SSH port number")
    flag.Parse()

    // Validate required parameters
    if *username == "" {
        fmt.Println("Error: username is required")
        flag.Usage()
        return
    }
    if *password == "" && *keyPath == "" {
        fmt.Println("Error: either password or key path must be provided")
        flag.Usage()
        return
    }

    // Get SSH configuration
    sshConfig := SSHConfig{
        Username: *username,
        Password: *password,
        KeyPath:  *keyPath,
        Port:     *port,
    }

    // Get known hosts
    homeDir, err := os.UserHomeDir()
    if err != nil {
        fmt.Printf("Error getting home directory: %v\n", err)
        return
    }
    
    sshDir := filepath.Join(homeDir, ".ssh")
    hosts, err := getAllKnownHosts(sshDir)
    if err != nil {
        fmt.Printf("Error parsing known hosts files: %v\n", err)
        return
    }

    fmt.Printf("\nTotal hosts found: %d\n", len(hosts))
    
    // Create channels for job distribution and results collection
    type LoginResult struct {
        Index    int
        Hostname string
        Error    error
    }
    
    const maxWorkers = 10 // Limit concurrent connections
    jobs := make(chan struct {
        index    int
        hostname string
    }, len(hosts))
    results := make(chan LoginResult, len(hosts))
    
    // Start worker pool
    for w := 0; w < maxWorkers; w++ {
        go func() {
            for job := range jobs {
                // Add small delay between attempts to prevent overwhelming servers
                time.Sleep(100 * time.Millisecond)
                
                err := trySSHLogin(job.hostname, sshConfig)
                results <- LoginResult{
                    Index:    job.index,
                    Hostname: job.hostname,
                    Error:    err,
                }
            }
        }()
    }
    
    // Send jobs to workers
    for i, host := range hosts {
        jobs <- struct {
            index    int
            hostname string
        }{i, host.Hostname}
    }
    close(jobs)
    
    // Collect and display results
    successCount := 0
    failCount := 0
    
    fmt.Printf("\nStarting login attempts to %d hosts with %d concurrent workers...\n", len(hosts), maxWorkers)
    
    for i := 0; i < len(hosts); i++ {
        result := <-results
        fmt.Printf("\n[%d] Login attempt to %s: ", result.Index+1, result.Hostname)
        if result.Error != nil {
            fmt.Printf("Failed - %v\n", result.Error)
            failCount++
        } else {
            fmt.Printf("Success\n")
            successCount++
        }
    }
    
    fmt.Printf("\nSummary:\n")
    fmt.Printf("Total attempts: %d\n", len(hosts))
    fmt.Printf("Successful: %d\n", successCount)
    fmt.Printf("Failed: %d\n", failCount)
}
