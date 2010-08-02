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
    fmt.Printf("Found value: %s\n", v)
        go func() {
        for {
       j:= node.AcceptStream(80)
       fmt.Printf("AcceptStream\n")
       go func () {for {
       j.Read()
       }
       }()
       }
    }()    
    connect_nodeid := dht.Bytetokey(&[...]byte("\x75\xb7\x7c\xdc\x82\x20\x46\xfa\x63\x13\x10\xd8\x66\x53\x97\x21\x93\xc1\xcb\x97"))
    

    h := node.StreamConnect(connect_nodeid, 80)
        f, _ := os.Open("/dev/urandom", os.O_RDONLY, 0666) 
        bb := make([]byte, 1000)
    if h != nil {
    for {
         f.Read(bb)
              fmt.Printf("Sending random stream data\n")
     h.Write(bb, true)
              fmt.Printf("Back\n")
    time.Sleep(100000)
    }
    }

    time.Sleep(11231928379128732)
    
}
