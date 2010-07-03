package dht


import . "container/vector"
import "net"
import "os"
import "crypto/rsa"
import "crypto/x509"
import "crypto/rand"
import "crypto/sha1"
import random "rand"
import "time"
import "encoding/binary"
import "bytes"
import "goprotobuf.googlecode.com/hg/proto"
import "fmt"
import "big"
import "sort"

const (
    K = 20
    Alpha = 3
    B = 160
    tExpire = 86400
    tRefresh = 3600
    tReplicate = 3600
    tRepublish = 86400
    MAXPKTSIZE = 4096
    MAXSTORESIZE = 64000
    TIMEOUT = 2000000000

)
type Key []byte

type InNodeDescriptor struct { /* In = internal */
    Addr *net.UDPAddr
    Behindnat bool
    Nodeid Key
    Session *UDPSession
    Publickey *rsa.PublicKey
    Bucket *Bucket
}


type Bucket struct {
    Node *Node
    v *Vector
    sortKey Key
}

    
func NewBucket(n *Node) *Bucket {
    b := new(Bucket)
    b.Node = n
    b.v = new(Vector)
    return b
}
func (this *Bucket) SetSortKey(key Key) {
    this.sortKey = key
}

func (this *Bucket) Len() int {
    return this.v.Len()
}
func (this *Bucket) Less(i,j int) bool {
    if this.sortKey == nil {
        distance1 := XOR(this.At(i).Nodeid, this.Node.Nodeid)
        distance2 := XOR(this.At(j).Nodeid, this.Node.Nodeid)
        return distance1.Less(distance2)
    } 
    distance1 := XOR(this.At(i).Nodeid, this.sortKey)
    distance2 := XOR(this.At(j).Nodeid, this.sortKey)
    return distance1.Less(distance2)
}
func (this *Bucket) At(i int) *InNodeDescriptor {
    return this.v.At(i).(*InNodeDescriptor) 
}
func (this *Bucket) Swap(i,j int) {
    this.v.Swap(i,j)
}
func (this *Bucket) Push(node *InNodeDescriptor) {
    this.v.Push(node)
}

func (this *Bucket) Pop() *InNodeDescriptor {
    return this.v.Pop().(*InNodeDescriptor)
}

func (this *Bucket) Cut(i,j int)  {
    this.v.Cut(i,j)
}
func (this *Bucket) Iter()  chan *InNodeDescriptor {
    ch := this.v.Iter()
    nodech := make(chan *InNodeDescriptor)
    go func(){
        for {
            if closed(ch) { close(nodech); return }
            m := (<-ch)
            if m == nil {close(nodech); return }
            nodech <- m.(*InNodeDescriptor)
        }
    }()
    return nodech
}



type Node struct {
    HotRoutine
    Buckets map[int]*Bucket
    Nodeid Key
    Reachable bool
    Keypair *rsa.PrivateKey
    Listenport int
    Handler *UDPHandler
    TotalNodes int
    Data Datastore
}

type Listener struct {
    Node *Node
    Port int
}

type UDPHandler struct {
    Buffer Buf
    Node *Node
    HotRoutine
    Conn *net.UDPConn
    FromMap map[string]chan Buf
    SessionChan chan *UDPSession
}
func NewUDPHandler(port int, node *Node) *UDPHandler {
    
    u := new(UDPHandler)
    laddr,_ := net.ResolveUDPAddr(fmt.Sprintf("0.0.0.0:%d",port))
    u.Conn,_ = net.ListenUDP("udp",laddr) 
    u.FromMap = make(map[string]chan Buf)
    u.SessionChan = make(chan *UDPSession)
    u.Node = node
    return u
}

type UDPSession struct {
    Handler *UDPHandler
    RAddr *net.UDPAddr
    HotRoutine
    Node *Node
    RecpNode *InNodeDescriptor
    IdMap map[int32]chan Buf
    Default chan Buf
    NeedToSendDesc bool //If the repicient needs the publickey
    NodeIsAdded bool //If the node is added to bucket
    First bool //Keep track of the first packet sent
}


type Buf []byte
func (b Buf) Write(p []byte) (int, os.Error) {
    copy(b,p)
    return len(p), nil
}
func (b Buf) Read(p []byte) (int, os.Error) {
    copy(p,b)
    return len(b), nil
}




func NewMsgId() int32 {
    return random.Int31()
}

func BucketNo(d Key) uint {
	var basebitnr uint = 0

	for _, b := range d {
		if b == 0 {
			basebitnr += 8
			continue
		}
		var bitnr uint = 0
		for i := 0; i < 8; i++ {
			if (b & (0x80 >> bitnr)) != 0 {
				return basebitnr + bitnr
			}
			bitnr++
		}
	}

	return basebitnr
}

func XOR(a, b Key) Key {
	l := len(a)
	if l != len(b) {
		return nil
	}

	d := make(Key, l)

	for i := 0; i < l; i++ {
		d[i] = a[i] ^ b[i]
	}

	return d
}


func (a Key) Less(b Key) bool {
	if len(a) != len(b) {
        return false
	}
	for i, ea := range a {
		eb := b[i]
		switch {
		case ea < eb:
			return true
		case ea > eb:
			return false
		default:
		}
	}
	return false
}



type hdr_n_data struct {
    header *Header
    data []byte
}


func (this *UDPSession) DecodePacket(data Buf) (*Header,[]byte, os.Error) {
    //Read header first
    var hdrlen uint32
    var datalen uint32
    if len(data) < 8 {
        fmt.Printf("len(data) < 8.. %x\n",  data)
        return nil,data,os.ENOMEM
    }
    err := binary.Read(data[0:4], binary.BigEndian, &hdrlen)
        if err != nil { return nil,data,err }
    err = binary.Read(data[4:8], binary.BigEndian, &datalen)
        if err != nil { return nil,data,err }
    if !(hdrlen < 2048 && datalen <= 8096 ) {
        fmt.Printf("Packet too big!\n")
        return nil,data,os.ENOMEM
    }

    header := NewHeader()
    err = proto.Unmarshal(data[8:8+hdrlen], header)
    if err != nil {
        return nil,data,err
    }
    newdata := make(Buf, datalen)
    copy(newdata,data[8+hdrlen:8+hdrlen+datalen])
    
    return header, newdata,nil
}
 
func (this *UDPSession) EncodePacket(data []byte, t,id,part int32, hmac,encrypted bool) []byte {
        newt := NewPktType(t)
        header := NewHeader()
        header.Type = newt
        header.Msgid = proto.Int32(id)
        header.Part = proto.Int32(part)
        header.Knowsyou = proto.Bool(this.NodeIsAdded)
        if this.NeedToSendDesc {
            //Include publickey
            header.From = this.Node.Descriptor()
        }
        hdrdata,err := proto.Marshal(header)
        if err != nil {
            fmt.Printf("%s\n", err)
            return nil
        }
        hdrlen := uint32(len(hdrdata))
        datalen :=  uint32(len(data))
        buffer := make(Buf, 8+hdrlen+datalen)
        binary.Write(buffer, binary.BigEndian, [2]uint32{hdrlen,datalen})
        copy(buffer[8:8+len(hdrdata)],hdrdata)
        copy(buffer[8+len(hdrdata):8+len(hdrdata)+len(data)], data) 
        return buffer
}



func NewUDPSession(raddr *net.UDPAddr, node *Node, udphandler *UDPHandler) *UDPSession {
    c := new(UDPSession)
    c.RAddr =  raddr
    c.Handler = udphandler
    c.Node = node
    c.First = true
    if c.Handler.FromMap[raddr.String()] == nil {
    c.Handler.FromMap[raddr.String()] = make(chan Buf)
    }
    c.IdMap = make(map[int32]chan Buf)
    go c.HotStart()
    
    return c
}

func (this *UDPHandler) Start() {
    go this.HotStart()
    fmt.Printf("UDPHandler started\n")
    this.Buffer = make(Buf, 10000)
    this.SessionChan = make(chan *UDPSession)
        go func() { for {
            n, addr, err := this.Conn.ReadFromUDP(this.Buffer)
            saddr := addr.String()
            if err != nil {fmt.Printf("%s", err); break}
            newbuf := make(Buf, n)
            copy(newbuf, this.Buffer)
            fmt.Printf("Checking if FromMap[saddr] is nil\n")
            if this.FromMap[saddr] == nil {
                this.FromMap[saddr] = make(chan Buf)
                session := NewUDPSession(addr, this.Node, this)
                go session.Start()
               go func() {this.SessionChan <- session} ()
            }
                go func() { this.FromMap[saddr]<-newbuf}()
            
        }
        }()
    
}

func (this *UDPHandler) GetSession() *UDPSession {
    s := <-this.SessionChan
    return s 
}


func (this *UDPSession) Start() {
    fmt.Printf("UDPSession started\n")
    this.Default = make(chan Buf)
    saddr := this.RAddr.String()
    if this.Handler.FromMap[saddr] == nil {
        this.Handler.FromMap[saddr] = make (chan Buf)
    }
    packetchan := this.Handler.FromMap[saddr]
    go func() {
        for {
            packet := <-packetchan
            if packet == nil {fmt.Printf("Error reading from UDPHandler"); break }
            header,_,err := this.DecodePacket(packet)
            if err != nil {
                fmt.Printf("Start·E: %s\n", err)
                continue
            }
            if header == nil {
                fmt.Printf("Header isn't valid\n")
                continue
            }

            if *header.Part >  0 {
                if this.IdMap[*header.Msgid] == nil{
                    this.IdMap[*header.Msgid] = make(chan Buf)
                }
                go func() { fmt.Printf("this.IdMap[%d]<-packet\n", *header.Msgid); this.IdMap[*header.Msgid]<-packet}()
            } else {
                go func() { this.Default <- packet }()
            }
            
            
        }
    } ()
    
    
    //(data []byte, t, id,part  int32, first,hmac,encrypted bool) bool 
    for {
        header, data := this.Read(0, 0)
        
        if header == nil { fmt.Printf("Header is nil :( \n"); continue }
                                fmt.Printf("The packet is of type %s\n", PktType_name[int32(*header.Type)])
        switch *header.Type {
            case PktType_STORE:
                p := NewStore()
                proto.Unmarshal(data,p)
                this.Node.Data.Set(p.Key, p.Value)
                answer := NewAnswerOk()
                answer.Ok = proto.Bool(true)
                adata,_ := proto.Marshal(answer)
                this.Send(adata, PktType_ANSWEROK, *header.Msgid, 1, false,false)
            case PktType_FINDNODE:
                p := NewFindNode()
                proto.Unmarshal(data,p)
                nodeid := p.Key
                close := this.Node.FindCloseNodes(nodeid)
                descriptors := make([]*NodeDescriptor, close.Len())
                l:=close.Len()
                fmt.Printf("There are %d close nodes\n", l)
                for  i:=0; i < l; i++ {
                    fmt.Printf("%x\n", keytobyte(close.At(i).Nodeid))
                    descriptors[i] = close.At(i).ToNodeDescriptor()
                }
                answer := NewAnswerFindNode()
                answer.Nodes = descriptors
                if *p.Findvalue {
                    answer.Value = this.Node.Data.Get(p.Key)
                }
                adata,err := proto.Marshal(answer)
                if err != nil { fmt.Printf("E: %s\n", err) }
                this.Send(adata, PktType_ANSWERNODES, *header.Msgid,1,false,false)
            case PktType_PING:
                a := NewPong()
                adata,err := proto.Marshal(a)
                if err != nil  {fmt.Printf("E: %s\n", err)}
                this.Send(adata, PktType_ANSWERPONG,*header.Msgid, 1, false,false)
        }
    }
    
}


func (this *UDPSession) _doStore(header *Header, packet *Store) {
    //This is the datastore mechanism.
    //Returns a AnswerOk
    
}

func DecodePublicKey(p *Publickey) *rsa.PublicKey {
    pk := new(rsa.PublicKey)
    pk.N = new(big.Int)
    pk.N.SetBytes(p.Modulus) 
    pk.E = int(*p.Exponent)
    return pk                      
}

func EncodePublicKey(p *rsa.PublicKey) *Publickey {
    pk := NewPublickey()
    pk.Modulus = p.N.Bytes() 
    pk.Exponent = proto.Int32(int32(p.E))
    return pk                      
}


func (this *Node) Descriptor() *NodeDescriptor {


    n := NewNodeDescriptor()
        n.Udpport = proto.Int32(int32(this.Listenport))
    n.Nodeid = this.Nodeid
    n.Behindnat = proto.Bool(this.Reachable)
    n.Publickey = EncodePublicKey(&this.Keypair.PublicKey)
    return n
}

func (this *UDPSession) AddRecpNode(from *NodeDescriptor) {
                    fmt.Printf("Read: Node in this session is not added\n")
                    //HMAC and publickey and nodedescriptor objects are mandatory for this first header. If not included, ignore
                    
                        //Add nodedescriptor to bucket
                        fmt.Printf("Adding node to bucket\n")
                        desc := new(InNodeDescriptor)
                        desc.Session = this
                        desc.Addr = this.RAddr
                        desc.Behindnat = *from.Behindnat
                        desc.Nodeid = from.Nodeid
                        
                        //Verify
                        pkmodulus := from.Publickey.Modulus
                        sha1hash := sha1.New()
                        sha1hash.Write(pkmodulus)
                        if bytes.Compare(sha1hash.Sum(), desc.Nodeid) != 0 {//If public key or nodeid is wrong
                            fmt.Printf("Verification failed\nSHA1 = %x\nNodeid = %x\n", sha1hash.Sum(), desc.Nodeid)
                            //self.Answer<-hdr_n_data{nil,nil}
                            //return
                            return
                        } else {
                            fmt.Printf("Verification succeded!!\nSHA1 = %x\nNodeid = %x\n", sha1hash.Sum(), keytobyte(desc.Nodeid))
                        }
                        pk := DecodePublicKey(from.Publickey)
                        desc.Publickey = pk
                        this.Node.AddNode(desc)
                        this.RecpNode = desc
                        this.NodeIsAdded = true
                    
            
}

func (this *UDPSession) Read(msgid int32, timeout int64)(*Header, []byte) {
    /*h := NewHot(func(shared map[string]interface{}){    
        defer func() {fmt.Printf("returning from read hot\n")}()
        
        self := shared["self"].(*GenericHot)
        */
        var data Buf
        var ticker *time.Ticker
        if timeout != 0  {
            ticker = time.NewTicker(timeout)
        }
        
        if msgid == 0 {
            if timeout != 0 {
            select {
                case data = <-this.Default:
                    break
                case <-ticker.C:
                    ticker.Stop()
                    fmt.Printf("Ticker problem. Timeout = %d\n", timeout)
                    //self.Answer<-hdr_n_data{nil,nil}
                    return nil,nil
                   
            }
            } else {
                data = <-this.Default
            }
            if this.RecpNode != nil {
            this.Node.MoveKeyToTop(this.RecpNode.Nodeid) //There is activity, so we move the nodeid to the top of the bucket
            }
            header,mdata,err := this.DecodePacket(data)
            
            //Set the NeedToSendDesc flag, if "Knowsyou" is set in packet
            if *header.Knowsyou { this.NeedToSendDesc = false } else { this.NeedToSendDesc = true }
            
            if err != nil { fmt.Printf("E: %s\n", err); /* self.Answer<-hdr_n_data{nil,nil}*/ return header,mdata} else {
              //If this is some of the first packets received  - needs perhaps to be added to bucket
              if !this.NodeIsAdded { this.AddRecpNode(header.From) }
              
              if header.Isencrypted != nil {
                //Decrypt the packet
                //
                //
              }
              return header,mdata
            }
        } else {
            if d,ok := this.IdMap[msgid]; !ok || d == nil { fmt.Printf("make(chan Buf)\n"); this.IdMap[msgid] = make(chan Buf) }
            if timeout == 0 {
                data =  <-this.IdMap[msgid]
                
            }  else {
                select {
                    case data =  <-this.IdMap[msgid]:
                        break
                    case <-ticker.C:
                        ticker.Stop()
                        //self.Answer<-hdr_n_data{nil,nil}
                        
                        return nil,nil 
                }
            }
            header,mdata,err := this.DecodePacket(data)
            
            if err != nil {fmt.Printf("Read·E: %s\n", err) }
            
            if err != nil { return nil,nil} else {
              //self.Answer<-hdr_n_data{header,mdata}
              if !this.NodeIsAdded { this.AddRecpNode(header.From) }
              return header,mdata
            }
        }   
        /*
    })
    this.QueryHot(h)
    *//*
    answer:=(<-h.Answer).(hdr_n_data)
   return answer.header,answer.data
   */
   
            return nil,nil
}

func (this *UDPSession) Send(data []byte, t, id,part  int32,hmac,encrypted bool) bool {
    //Check if we have publickey

    
    if encrypted {
        if this.RecpNode.Publickey == nil {
            //Return false, because we need the public key
            return false
        } 
    }
        if this.NeedToSendDesc {    fmt.Printf("NeedToSendDesc flag is set\n") }
    pdata := this.EncodePacket(data,t,id,part,hmac,encrypted)
    fmt.Printf("Sending with msgid: %d to %s\n", id, this.RAddr)

    this.Handler.Conn.WriteTo(pdata,this.RAddr)
    if this.RecpNode != nil { 
    this.Node.MoveKeyToTop(this.RecpNode.Nodeid)  
    }
    return true
}

func (this *UDPSession) Ping() bool { 
    msgid := NewMsgId()
    ping_packet := NewPing()
    ping_data,_ := proto.Marshal(ping_packet)
    this.Send(ping_data, PktType_PING, msgid, 0, false,false)
    header,data := this.Read(msgid,2000000000)
    if header == nil || data == nil {
        return false
    }
    if *header.Type == PktType_ANSWERPONG {
        return true
    }
    return false
}

//REturns the unmarshalled protobuf packet
func (this *UDPSession) _findNode(key Key, findvalue bool) *AnswerFindNode{
    msgid := NewMsgId()
    m := NewFindNode()
    m.Key = key
    m.Findvalue = proto.Bool(findvalue)
    data, _ := proto.Marshal(m)
    fmt.Printf("Sending FINDNODE packet\n")
    this.Send(data, PktType_FINDNODE, msgid, 0, true,false)
 
    header,data := this.Read(msgid,TIMEOUT)
    if header == nil {
        return nil
    }
    fmt.Printf("Answer is of type: %s\n\n", PktType_name[int32(*header.Type)])
    if *header.Type == PktType_ANSWERNODES {
        fmt.Printf("Got an answer!\n")
        answer := NewAnswerFindNode()
        proto.Unmarshal(data,answer)
        return answer 
    } 
    return nil
}



/*
message NodeDescriptor { //Like a "from" field
    required int32 udpport = 1;
    required bool behindnat = 2;
    required bytes nodeid = 3;
    optional Publickey publickey = 4;
    optional bytes ipaddr = 5;
}
*/
/*

type InNodeDescriptor struct {
    Addr *net.UDPAddr
    Behindnat bool
    Nodeid []byte
    Session *UDPSession
    Publickey *rsa.PublicKey
    Bucket *Bucket
}
*/
func (this *NodeDescriptor) ToInNodeDescriptor() *InNodeDescriptor {
    innode := new(InNodeDescriptor)
    innode.Behindnat = *this.Behindnat
    innode.Nodeid = make(Key, B/8)
    copy(innode.Nodeid, this.Nodeid)
    if this.Publickey != nil {
        innode.Publickey = DecodePublicKey(this.Publickey)
    }
    innode.Addr = new(net.UDPAddr)
    innode.Addr.Port = int(*this.Udpport)
    if this.Ipaddr != nil {
        innode.Addr.IP = this.Ipaddr
    }
    return innode
}

func (this *InNodeDescriptor) ToNodeDescriptor() *NodeDescriptor {
    node := NewNodeDescriptor()
    node.Behindnat = proto.Bool(this.Behindnat)
    node.Nodeid = make(Key, B/8)
    copy(node.Nodeid, this.Nodeid)
    if this.Publickey != nil {
        node.Publickey = EncodePublicKey(this.Publickey)
    }
    node.Udpport = proto.Int(this.Addr.Port)
    node.Ipaddr = this.Addr.IP
    fmt.Printf("node.Ipaddr = %x\n", node.Ipaddr)
    return node        
}
    
func (this *UDPSession) FindNode(key Key) *Bucket {

    answer := this._findNode(key, false)
    fmt.Printf("Got the answer: %s\n", answer)
    nodes := NewBucket(this.Node)
    if answer != nil {
        if len(answer.Nodes) == 0 { return nil }
        fmt.Printf("Trying to add the nodes\n")
        for _,v := range answer.Nodes {
            fmt.Printf("A: %x\n", v.Nodeid)
            innode := v.ToInNodeDescriptor()
            nodes.Push(innode)
            this.Node.AddNode(innode)
        }
    } else { return nil }
    return nodes
}
func (this *UDPSession) FindValue(key Key) (*Bucket, []byte) {
    answer := this._findNode(key, true)
    fmt.Printf("Got the answer: %s\n", answer)
    nodes := NewBucket(this.Node)
    if answer != nil {
        if answer.Value != nil {
            return nil,answer.Value
        }
        fmt.Printf("Trying to add the nodes\n")
        for _,v := range answer.Nodes {
            innode := v.ToInNodeDescriptor()
            nodes.Push(innode)
            this.Node.AddNode(innode)
        }
    }
    return nodes,nil
}

func (this *UDPSession) Store(key Key, value []byte) bool {
    msgid := NewMsgId()
    m := NewStore()
    m.Key = key
    m.Value = value
    if len(value) > 3000 {  //Split it up in multiple packets 
    } else {
        mdata,_ := proto.Marshal(m)
        this.Send(mdata,PktType_STORE, msgid, 0,true,false)
        if this.IsAccepted(msgid) {
            return true
        }
    }
    return false
}
func (this *UDPSession) IsAccepted(msgid int32) bool {
    header, _ := this.Read(msgid,0)
    if *header.Type == PktType_ANSWEROK {
        return true
    }
    return false
}

func NewNode() *Node {
    n := new(Node)
    n.Buckets = make(map[int]*Bucket)
    n.Data = NewSimpleDatastore()
    go n.HotStart()
    return n
}



func (this *Node) FindCloseNodes(key Key) *Bucket {
    distance := XOR(key, this.Nodeid)

    closenodes := NewBucket(this)
    var ichan chan *InNodeDescriptor
    var first int
    var leap int = 1
    
    first = int(BucketNo(distance))
    if this.Buckets[first] == nil {
        this.Buckets[first] = NewBucket(this)
    }
    ichan = this.Buckets[first].Iter()
    for closenodes.Len() < K {
        if (first + leap) >= 159 &&  ( first - leap) < 0 {
           break
        }
        if closed(ichan) {
        
            if  first+leap <= 160 && this.Buckets[first + leap] != nil {
                ichan = this.Buckets[first + leap].Iter()
            }
            if first - leap >= 0 && this.Buckets[first - leap] != nil{
                ichan = this.Buckets[first - leap].Iter()
            }
            leap ++
        } 
        m := <-ichan
        if m == nil {

            if  first+leap <= 160 && this.Buckets[first + leap] != nil {
                ichan = this.Buckets[first + leap].Iter()
            }
            if first - leap >= 0 && this.Buckets[first - leap] != nil{
                ichan = this.Buckets[first - leap].Iter()
            }
            leap ++
        } else {
        closenodes.Push(m)
        }
    }
    
    return closenodes
}
func (this *Node) HasNode(key Key) (bool, *InNodeDescriptor) {
    distance := XOR(this.Nodeid,key)
    no := int(BucketNo(distance))
    ch := this.Buckets[no].Iter() 
    for {
        if closed(ch) {break }
        n := <-ch
        if n == nil {break }
        if bytes.Compare(n.Nodeid, key) == 0 { return true, n}
    }
    return false, nil
    
}
func (this *Node) AddNode(node *InNodeDescriptor) bool  {
    h := NewHot(func(shared map[string]interface{}){
        self := shared["self"].(*GenericHot)
        distance := XOR(this.Nodeid,node.Nodeid)
        no := int(BucketNo(distance))
        
        
        if this.Buckets[no] == nil {
            this.Buckets[no] = NewBucket(this)
        }
        if ok,n := this.HasNode(node.Nodeid); ok {
            fmt.Printf("Already have this node: %x\n", keytobyte(node.Nodeid))
            
            //HACK
            node.Session= n.Session
            node.Addr = n.Addr
            
            
            self.Answer <- false
            return
        }
        if bytes.Compare(node.Nodeid, this.Nodeid) == 0 {
            fmt.Printf("This is myself: %x\n", keytobyte(node.Nodeid))
            self.Answer <- false
            return 
        }
        fmt.Printf("Adding %x - %s\n",  keytobyte(node.Nodeid), node.Addr)
        this.TotalNodes++
        fmt.Printf("\n\nTotal node count = %d\n\n", this.TotalNodes)
        if node.Session == nil {
            node.Session = NewUDPSession(node.Addr,this,this.Handler)
            node.Session.NodeIsAdded = true
            node.Session.NeedToSendDesc= true
            go node.Session.Start()
            time.Sleep(10000000)
        }
        if this.Buckets[no].Len() >= K  {
            fmt.Printf("BUCKET IS FULL - TRYING TO PING\n")
            fmt.Printf("this.Buckets[no].At(0).Session.RAddr =%s\n", this.Buckets[no].At(0).Session.RAddr)
            go func() {
                if !(this.Buckets[no].At(0).Session.Ping()) {
                    this.Buckets[no].Cut(0,1)
                     this.Buckets[no].Push(node)
                     self.Answer<-true
                } else {
                     self.Answer<-false 
                }
            }()
        } else {
                 this.Buckets[no].Push(node)
                         self.Answer<-true
        }
        


 
    })
    this.QueryHot(h)
    answer:=(<-h.Answer).(bool)
    return answer
}







//Internal
func (this *Node) _iterFindNode(session *UDPSession,key Key, ch chan *Bucket, progress int, cancel *bool, alreadyAsked *Bucket) {
    if alreadyAsked == nil {
        alreadyAsked = NewBucket(this)
    }
    
    var nodes *Bucket
    nodes = session.FindNode(key)
    if nodes == nil { return }
    nodes.SetSortKey(key)
    sort.Sort(nodes)
    ich := nodes.Iter()
    L1: for {
        if closed(ich) { break }
        inode:=<-ich
        if inode == nil {
            break
        }
        if bytes.Compare(inode.Nodeid,this.Nodeid) == 0 { //If this is ourself
            continue
        }
        
            if bytes.Compare(inode.Nodeid, key) == 0 {
                ch <- nodes
                return
            }
        
        if *cancel { return }
        if progress == 3 {
            ch <- nodes
            return
        }
        j := alreadyAsked.Iter()
        for {
            if closed(j) {break}
            m := <-j
            if m == nil {break}
            
            if bytes.Compare(m.Nodeid, inode.Nodeid) == 0 {break L1 }
        }
        
        fmt.Printf("Asking %x for peers\n", keytobyte(inode.Nodeid))
        newnodes := inode.Session.FindNode(key)
        alreadyAsked.Push(inode)
        if newnodes == nil {
            continue
        } 
        newnodes = this.FindCloseNodes(key)
        newnodes.SetSortKey(key)
        sort.Sort(newnodes)
        ich = newnodes.Iter()
        for {
            if closed(ich) {break}
            n := <-ich
            if n == nil { break }
            if bytes.Compare(n.Nodeid, key) == 0 {
                ch <- newnodes
                return
            }
        }
        
        if newnodes.Len() > 0 {
            
            if XOR(newnodes.At(0).Nodeid, key).Less( XOR(inode.Nodeid, key) ) {
                fmt.Printf("\n\n\n%x <  %x, Iterating further\n\n", keytobyte(XOR(newnodes.At(0).Nodeid, key)), keytobyte(XOR(inode.Nodeid, key)))
                this._iterFindNode(newnodes.At(0).Session, key, ch, 0,cancel, alreadyAsked)
            } else {
                progress ++
                continue
            }
        }        
        /*
        ich = newnodes.Iter()
        for {
            if closed(ich) { break }
            ninode := <-ich
            if ninode == nil {break}
            if *cancel  { return }
            if bytes.Compareninode.Nodeid


            } else {
                continue
                //this._iterFindNode(ninode.Session, key, ch, progress+1,cancel)
            }
        }
        */
    }
    time.Sleep(TIMEOUT)
    ch <- nodes
}


//Internal
func (this *Node) _iterFindValue(session *UDPSession,key Key, ch chan v_answer, progress int, cancel *bool, alreadyAsked *Bucket) {
    if alreadyAsked == nil {
        alreadyAsked = NewBucket(this)
    }
    
    var nodes *Bucket
    nodes,value := session.FindValue(key)
    
        if value != nil {
            ch <- v_answer{nil,value}
            return
        }
    if nodes == nil { return }
    nodes.SetSortKey(key)
    sort.Sort(nodes)
    ich := nodes.Iter()
    L1: for {
        if closed(ich) { break }
        inode:=<-ich
        if inode == nil {
            break
        }
        if bytes.Compare(inode.Nodeid,this.Nodeid) == 0 { //If this is ourself
            continue
        }
        
            if bytes.Compare(inode.Nodeid, key) == 0 {
                ch <- v_answer{nodes,nil}
                return
            }
        
        if *cancel { return }
        if progress == 3 {
            return
        }
        j := alreadyAsked.Iter()
        for {
            if closed(j) {break}
            m := <-j
            if m == nil {break}
            
            if bytes.Compare(m.Nodeid, inode.Nodeid) == 0 {break L1 }
        }
        
        fmt.Printf("Asking %x for peers\n", keytobyte(inode.Nodeid))
        newnodes,value := inode.Session.FindValue(key)
        alreadyAsked.Push(inode)
        if value != nil {
            ch <- v_answer{newnodes,value}
            return
        }
        if newnodes == nil {
            continue
        } 
        newnodes = this.FindCloseNodes(key)
        newnodes.SetSortKey(key)
        sort.Sort(newnodes)
        ich = newnodes.Iter()
        for {
            if closed(ich) {break}
            n := <-ich
            if n == nil { break }
            if bytes.Compare(n.Nodeid, key) == 0 {
                ch <- v_answer{newnodes,nil}
                return
            }
        }
        
        if newnodes.Len() > 0 {
            
            if XOR(newnodes.At(0).Nodeid, key).Less( XOR(inode.Nodeid, key) ) {
                fmt.Printf("\n\n\n%x <  %x, Iterating further\n\n", keytobyte(XOR(newnodes.At(0).Nodeid, key)), keytobyte(XOR(inode.Nodeid, key)))
                this._iterFindValue(newnodes.At(0).Session, key, ch, 0,cancel, alreadyAsked)
            } else {
                progress ++
                continue
            }
        }        
        /*
        ich = newnodes.Iter()
        for {
            if closed(ich) { break }
            ninode := <-ich
            if ninode == nil {break}
            if *cancel  { return }
            if bytes.Compareninode.Nodeid


            } else {
                continue
                //this._iterFindNode(ninode.Session, key, ch, progress+1,cancel)
            }
        }
        */
    }
}


func (this *Node) IterativeFindNode(key Key) *Bucket {
    hasnodes := this.FindCloseNodes(key)
    hasnodes.SetSortKey(key)
    sort.Sort(hasnodes)
    
    
    cancel := new(bool)
    *cancel = false
    
    ch := make(chan *Bucket)
    fmt.Printf("Length of hasnodes = %d\n", hasnodes.Len())
    for i:= 0; i < hasnodes.Len()  && i < Alpha; i++ {
            ic := i
            go func() {
                        fmt.Printf("hasnodes.At(%d)\n", ic)
                inode := hasnodes.At(ic)
                if inode != nil {
                    this._iterFindNode(inode.Session, key,ch,0,cancel, nil)
                }
            }()
    }
    nodes := <-ch
    *cancel = true
    return nodes
    
}

type v_answer struct {
    nodes *Bucket
    value []byte
}
func (this *Node) IterativeFindValue(key Key) (*Bucket,[]byte) {
    hasnodes := this.FindCloseNodes(key)
    hasnodes.SetSortKey(key)
    sort.Sort(hasnodes)
    
    
    cancel := new(bool)
    *cancel = false
    
    ch := make(chan v_answer)
    fmt.Printf("Length of hasnodes = %d\n", hasnodes.Len())
    for i:= 0; i < hasnodes.Len()  && i < Alpha; i++ {
            ic := i
            go func() {
                        fmt.Printf("hasnodes.At(%d)\n", ic)
                inode := hasnodes.At(ic)
                if inode != nil {
                    this._iterFindValue(inode.Session, key,ch,0,cancel, nil)
                }
            }()
    }
    v := <-ch
    *cancel = true
    return v.nodes,v.value
    
}




func (this *Node) IterativeStore(key Key, value []byte) {
    closenodes := this.IterativeFindNode(key)
    fmt.Printf("back from iterativefindnode\n")
    ch := closenodes.Iter()
    for {
        if closed(ch) { break }
        m := <-ch
        if m == nil {break}
        fmt.Printf("Trying to STORE\n")
        m.Session.Store(key, value)
    }
}

func (this *Node) MoveKeyToTop(key Key) {
    h := NewHot(func(shared map[string]interface{}){
        self := shared["self"].(*GenericHot)
            distance := XOR(key,this.Nodeid)
            no := int(BucketNo(distance))
            b,ok := this.Buckets[no]
            if b == nil || !ok {return }
            ch := b.Iter()
            var position int = 0
            for i := 0; ; i++ {
                if closed(ch) { break}
                m := <-ch
                if m == nil {break }
                if bytes.Compare(key,m.Nodeid) == 0 { position = i }
            }
            for i := position; i>0; i-- {
                this.Buckets[no].Swap(i, i-1)
            }        
            self.Answer <- true
    })
    this.QueryHot(h)
    <-h.Answer
    return
}
func GeneratePrivateKey(filename string) {
        os.Open(filename, os.O_CREAT, 0644)
        f,err := os.Open(filename, os.O_WRONLY, 0644)
        if err != nil { fmt.Printf("%s\n", err); return }
        fmt.Printf("Generating key... \n")
        pk,_ := rsa.GenerateKey(rand.Reader, 768)
        fmt.Printf("Done.. Marshalling\n")
        pkdata := x509.MarshalPKCS1PrivateKey(pk)
        fmt.Printf("Done\n")
        _,err = f.Write(pkdata)
                if err != nil { fmt.Printf("%s\n", err); return }
        
        f.Close()
    
}
func (this *Node) Bootstrap(port int, known string, privatekey string) bool {
    knownhost,err := net.ResolveUDPAddr(known)
    if err != nil {
        fmt.Printf("E: %s\n", err)
        return false
    }
    random.Seed(time.Nanoseconds())

    //Establish private key
    f, err := os.Open(privatekey, os.O_RDONLY, 0666) 
    if err != nil {
        return false
    }

        fi,err := os.Stat(privatekey)
    size := int(fi.Size)
    pkdata := make([]byte, size)
    f.Read(pkdata)

    keypair,err :=  x509.ParsePKCS1PrivateKey(pkdata)
            if err != nil { fmt.Printf("%s\n", err); return false }
    this.Keypair = keypair
    
    sha1hash := sha1.New()
    sha1hash.Write(this.Keypair.PublicKey.N.Bytes())
    this.Nodeid = Key(sha1hash.Sum())
    fmt.Printf("This nodes id: %x\n", keytobyte(this.Nodeid))
    this.Reachable = true
   
    
    //Start the listener
    fmt.Printf("Starting the UDPHandler..\n")
    udphandler := NewUDPHandler(port,this)
    this.Handler = udphandler
    go udphandler.Start()
    
    
    //Connect to known host
    fmt.Printf("Connecting to known host\n")
    if err != nil { fmt.Printf("%s\n", err) }
    c := NewUDPSession(knownhost,this,udphandler)
    c.Node = this
    c.NodeIsAdded = false
    c.NeedToSendDesc = true
    go c.Start()
    c.FindNode(this.Nodeid)
    this.IterativeFindNode(this.Nodeid)
    return true
}

func keytobyte(key Key) []byte {
    return key
}
