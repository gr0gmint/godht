package dht

import "net"
import "fmt"
import "json"
import "os"

//I'm not implementing this part as JSON-RPC because of some limitations it has.

type JSONRequest struct {
    Action string
    Parameters map[string]interface{}
}
func NewJSONRequest() *JSONRequest {
    j := new(JSONRequest)
    j.Parameters = make(map[string]interface{})
    return j
}

type JSONInterface struct {
    Node *Node
    Conn net.Conn
}
func NewJSONInterface(node *Node, c net.Conn) *JSONInterface {
    j := new(JSONInterface)
    j.Node = node
    j.Conn = c
    return j
}
func (this *JSONInterface) Start() {
    for {
        d := json.NewDecoder(this.Conn)
        req := NewJSONRequest()
        err := d.Decode(req)
        if err != nil {
            fmt.Printf("%s\n", err)
            break
        }
        switch req.Action {
            case "stream":
                fmt.Printf("It's a stream request\n")
                port := int32(req.Parameters["port"].(float64))
                nodeid_string := req.Parameters["nodeid"].(string)
                nodeid := make([]byte, 20)
                _,err := fmt.Sscanf(nodeid_string, "%x", &nodeid)
                if err != nil { fmt.Printf("%s\n", err ); break }
                fmt.Printf("nodeid: %x\n", nodeid)
                this.PipeStream(nodeid, port)
            case "store":
                
        }
    }
}
func (this *JSONInterface) PipeStream(nodeid Key, port int32) {
    in := make(chan []byte)
    out := make( chan []byte)
    fmt.Printf("before StreamConnect\n")
    streamhandler := this.Node.StreamConnect(nodeid, port)
    fmt.Printf("after StreamConnect\n")
    if streamhandler == nil { return }
    
    go func () {
        for {
            b,err  := streamhandler.Read()
            if err != nil { in <- nil; return }
            in <- b
        }  
    }()
    
    go func () {
        b := make ([]byte,3000)
        for {
            n,err := this.Conn.Read(b)
            if err != nil { out <- nil; return }
            bn := make([]byte, n)
            copy (bn, b)
            out <- bn
        }
    }()
    for {
        select {
            case b := <- in:
                if b == nil {return}
                this.Conn.Write(b)
            case b := <- out:
                if b == nil {return}
                streamhandler.Write(b,true)
        }
    }
}
func ListenJSON(node *Node,port int) os.Error {
    laddr,err := net.ResolveTCPAddr(fmt.Sprintf("127.0.0.1:%d", port))
    if err != nil { return err }
    l,err := net.ListenTCP("tcp", laddr)
    if err != nil { return err }
    
    fmt.Printf("JSON interface is listening\n")
    for {
        c, _ := l.Accept()
        fmt.Printf("Accepted one\n")
        j := NewJSONInterface(node,c)
        go j.Start()
    }
    
    return nil
}
