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
    node.Bootstrap(port, os.Args[2], filename)
    key := dht.Key{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20}
    valuestring := "这根俺还子在跑步！"
    value := bytes.NewBufferString(valuestring)
    fmt.Printf("Trying a iterativestore now\n")
    node.IterativeStore(key,value)
    fmt.Printf("Returned from IterativeStore\n")
    _,v := node.IterativeFindValue(key)
    fmt.Printf("Found value: %s", v)

    connect_nodeid := dht.Bytetokey(&[...]byte("\x75\xb7\x7c\xdc\x82\x20\x46\xfa\x63\x13\x10\xd8\x66\x53\x97\x21\x93\xc1\xcb\x97"))
    h := node.StreamConnect(connect_nodeid, 80)
    if h != nil {
     h.Write(connect_nodeid, true)
    }
        go func() {
       j:= node.AcceptStream(80)
       fmt.Printf("AcceptStream\n")
       j.Read()
    }()
    time.Sleep(11231928379128732)
    
}
