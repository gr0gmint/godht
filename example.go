package main
import "dht"
import "os"
import "strconv"
import "bytes"
import "fmt"
import "time"

func main() {
    if len(os.Args) < 4 {
        fmt.Printf("Usage:  ./8.out <listenport> <knownhost> <path-to-keypair> [<JSON-interface listenport>]\n")
        return
    }
    
    node := dht.NewNode()
    port,_ := strconv.Atoi(os.Args[1])

    filename := os.Args[3]
        _,err := os.Stat(filename)
            if err != nil { dht.GeneratePrivateKey(filename)}
    node.Bootstrap(port, os.Args[2], filename)
    key := dht.Key{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20}
    valuestring := "这根俺还子在跑步！"
    value := bytes.NewBufferString(valuestring)
    fmt.Printf("Trying a iterativestore now\n")
    node.IterativeStore(key,value)
    fmt.Printf("Returned from IterativeStore\n")
    _,v := node.IterativeFindValue(key)
    fmt.Printf("Found value: %s\n", v)
    if len(os.Args) == 5 {
    var jsonport int
    fmt.Sscanf(os.Args[4], "%d", &jsonport)
    go func() { err := dht.ListenJSON(node,jsonport); if err != nil {fmt.Printf("%s\n", err) }}()
    }
    time.Sleep(123123123912314)   
}
