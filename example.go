package main
import "dht"
import "os"
import "strconv"
import "time"
func main() {
    node := dht.NewNode()
    port,_ := strconv.Atoi(os.Args[1])

    filename := os.Args[3]
        _,err := os.Stat(filename)
            if err != nil { dht.GeneratePrivateKey(filename)}
                node.Bootstrap(port, os.Args[2], filename)
    time.Sleep(100000000000)
}
