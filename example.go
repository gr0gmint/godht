package main
import "dht"
import "os"
import "strconv"
import "time"
import "bytes"
import "fmt"

func main() {
    node := dht.NewNode()
    port,_ := strconv.Atoi(os.Args[1])

    filename := os.Args[3]
        _,err := os.Stat(filename)
            if err != nil { dht.GeneratePrivateKey(filename)}
                go node.Bootstrap(port, os.Args[2], filename)
    time.Sleep(1000000000)
    key := dht.Key{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20}
    valuestring := "这根俺还子在跑步！"
    value := (bytes.NewBufferString(valuestring)).Bytes()
    fmt.Printf("Trying a iterativestore now\n")
    node.IterativeStore(key,value)
    time.Sleep(99999999999999999)   
}
