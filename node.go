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

)
type Key []byte

type InNodeDescriptor struct { /* In = internal */
    Addr *net.UDPAddr
    Behindnat bool
    Nodeid []byte
    Session *UDPSession
    Publickey *rsa.PublicKey
    Bucket *Bucket
}


type Bucket struct {
    Node *Node
    v Vector
}
    
func NewBucket(n *Node) *Bucket {
    b := new(Bucket)
    b.Node = n
    return b
}
func (this *Bucket) Len() int {
    return this.v.Len()
}
func (this *Bucket) Less(i,j int) bool {
    distance1 := XOR(this.At(i).Nodeid, this.Node.Nodeid)
    distance2 := XOR(this.At(j).Nodeid, this.Node.Nodeid)
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
            nodech <- (<-ch).(*InNodeDescriptor)
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
    FromMap map[*net.UDPAddr]chan Buf
    SessionChan chan *UDPSession
}
func NewUDPHandler(port int, node *Node) *UDPHandler {
    
    u := new(UDPHandler)
    laddr,_ := net.ResolveUDPAddr(fmt.Sprintf("0.0.0.0:%d",port))
    u.Conn,_ = net.ListenUDP("udp",laddr) 
    u.FromMap = make(map[*net.UDPAddr]chan Buf)
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
    FirstPacketSent bool //If the repicient needs the publickey
    NodeIsAdded bool //If the node is added to bucket
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
        return nil,data,os.ENOMEM
    }
    err := binary.Read(data[0:4], binary.BigEndian, &hdrlen)
        if err != nil { return nil,data,err }
    err = binary.Read(data[4:8], binary.BigEndian, &datalen)
        if err != nil { return nil,data,err }
    if !(hdrlen < 512 && datalen <= 4096 ) {
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
 
func (this *UDPSession) EncodePacket(data []byte, t,id,part int32, first,hmac,encrypted bool) []byte {
        newt := NewPktType(t)
        header := NewHeader()
        header.Type = newt
        header.Msgid = proto.Int32(id)
        header.Part = proto.Int32(part)
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
        go c.HotStart()
    return c
}

func (this *UDPHandler) Start() {
    go this.HotStart()
    fmt.Printf("UDPHandler started\n")
    this.Buffer = make(Buf, 10000)
    this.SessionChan = make(chan *UDPSession)
        for {
            n, addr, err := this.Conn.ReadFromUDP(this.Buffer)
            if err != nil {fmt.Printf("%s", err); break}
            newbuf := make(Buf, n)
            copy(newbuf, this.Buffer)
            fmt.Printf("Checking if FromMap[addr] is nil\n")
            if this.FromMap[addr] == nil {
                this.FromMap[addr] = make(chan Buf)
                fmt.Printf("Created a chan\n")
                session := NewUDPSession(addr, this.Node, this)
                go session.Start()
                go func() {this.SessionChan <- session} ()
            }
                go func() { this.FromMap[addr]<-newbuf}()
            
        }
    
}

func (this *UDPHandler) GetSession() *UDPSession {
    s := <-this.SessionChan
    return s 
}


func (this *UDPSession) Start() {
    fmt.Printf("UDPSession started\n")
    this.Default = make(chan Buf)
    if this.Handler.FromMap[this.RAddr] == nil {
        this.Handler.FromMap[this.RAddr] = make (chan Buf)
    }
    packetchan := this.Handler.FromMap[this.RAddr]
    go func() {
        for {
            packet := <-packetchan
            if packet == nil {fmt.Printf("Error reading from UDPHandler"); break }
            header,data,err := this.DecodePacket(packet)
            if err != nil {
                fmt.Printf("E: %s\n", err)
            }
            fmt.Printf("Got a packet: %s\n", data)
            if header == nil {
                fmt.Printf("Header isn't valid\n")
                continue
            }
            if *header.Part >  0 {
                if this.IdMap[*header.Msgid] == nil {
                    this.IdMap[*header.Msgid] = make(chan Buf)
                }
                go func() { this.IdMap[*header.Msgid]<-packet}()
            } else {
                go func() { this.Default <- packet }()
            }
            
            
        }
    } ()
    for {
        this.Read(0, 0)
    }
    
}

func (this *UDPSession) Read(msgid int32, timeout int64)(*Header, []byte) {
    h := NewHot(func(shared map[string]interface{}){     
        self := shared["self"].(*GenericHot)
        var data Buf
        var ticker *time.Ticker
        if timeout != 0  {
            ticker = time.NewTicker(timeout)
        }
        if msgid == 0 {
            if timeout != 0 {
            select {
                case data = <-this.Default:
                case <-ticker.C:
                    ticker.Stop()
                    self.Answer<-hdr_n_data{nil,nil}
                    return
            }
            } else {
                data = <-this.Default
            }
            header,mdata,err := this.DecodePacket(data)
            if err != nil { self.Answer<-hdr_n_data{nil,nil}} else {
              //If this is some of the first packets received  - needs perhaps to be added to bucket
                if !this.NodeIsAdded {
                    //HMAC and publickey and nodedescriptor objects are mandatory for this first header. If not included, ignore
                    if header.Hmac == nil || header.From == nil || header.From.Publickey == nil {
                        self.Answer<-hdr_n_data{nil,nil}
                        return
                    } else {
                        //Add nodedescriptor to bucket
                       
                        desc := new(InNodeDescriptor)
                        desc.Session = this
                        desc.Addr = this.Handler.Conn.RemoteAddr().(*net.UDPAddr)
                        desc.Behindnat = *header.From.Behindnat
                        desc.Nodeid = header.From.Nodeid
                        
                        //Decode public key
                        pkmodulus := header.From.Publickey.Modulus
                        sha1hash := sha1.New()
                        sha1hash.Write(pkmodulus)
                        if bytes.Compare(sha1hash.Sum(), desc.Nodeid) != 0 {//If public key or nodeid is wrong
                            self.Answer<-hdr_n_data{nil,nil}
                            return
                        }
                        pk := new(rsa.PublicKey)
                        pk.N = new(big.Int)
                        pk.N.SetBytes(header.From.Publickey.Modulus) 
                        pk.E = int(*header.From.Publickey.Exponent)
                        desc.Publickey = pk
                        
                        if this.Node.AddNode(desc) {
                            this.RecpNode = desc
                            this.NodeIsAdded = true
                        }
                    }
            
                }
              if header.Isencrypted != nil {
                //Decrypt the packet
                //
                //
              }
              self.Answer<-hdr_n_data{header,mdata}
            }
            return
        } else {
            if this.IdMap[msgid] == nil { this.IdMap[msgid] = make(chan Buf) }
            if timeout == 0 {
                data =  <-this.IdMap[msgid]
            }  else {
                select {
                    case data =  <-this.IdMap[msgid]:
                    case <-ticker.C:
                        ticker.Stop()
                        self.Answer<-hdr_n_data{nil,nil}
                        return 
                }
            }
                        header,mdata,err := this.DecodePacket(data)
            if err != nil { self.Answer<-hdr_n_data{nil,nil}} else {
              self.Answer<-hdr_n_data{header,mdata}
            }
            return
        }   
        
    })
    this.QueryHot(h)
    answer:=(<-h.Answer).(hdr_n_data)
   return answer.header,answer.data
}

func (this *UDPSession) Send(data []byte, t, id,part  int32, first,hmac,encrypted bool) bool {
    //Check if we have publickey

    
    if encrypted {
        if this.RecpNode.Publickey == nil {
            //Return false, because we need the public key
            return false
        } 
    }

    pdata := this.EncodePacket(data,t,id,part,first,hmac,encrypted) 
    this.Handler.Conn.WriteTo(pdata,this.RAddr)   
    return true
}

func (this *UDPSession) Ping() bool {
    msgid := NewMsgId()
    ping_packet := NewPing()
    ping_data,_ := proto.Marshal(ping_packet)
    this.Send(ping_data, PktType_PING, msgid, 0,false, false,false)
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
    this.Send(data, PktType_FINDNODE, msgid, 0, false,true,false)
    fmt.Printf("Waiting for answer....\n")
    header,data := this.Read(msgid,0 )
    if *header.Type == PktType_ANSWERNODES {
        answer := NewAnswerFindNode()
        err :=proto.Unmarshal(data,answer)
        if err != nil {
        return answer
        }
    } 
    return nil
}
func (this *UDPSession) FindNode(key Key) {
    answer := this._findNode(key, false)
    if answer != nil {
        
    }
    
} 


func (this *UDPSession) Store(key Key, value []byte) bool {
    msgid := NewMsgId()
    m := NewStore()
    m.Key = key
    m.Value = value
    if len(value) > 3000 {  //Split it up in multiple packets 
    } else {
        mdata,_ := proto.Marshal(m)
        this.Send(mdata,PktType_STORE, msgid, 0,false,true,false)
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
    return n
}



func (this *Node) FindCloseNodes(key Key) *Bucket {
    distance := XOR(key, this.Nodeid)

    closenodes := NewBucket(this)
    var ichan chan *InNodeDescriptor
    var first int
    var leap int
    var goleft bool = true
    
    first = int(BucketNo(distance))
    ichan = this.Buckets[first].Iter()
    for closenodes.Len() < K {
        if closed(ichan) {
            if goleft {
                if first - leap <= 0 {
                    goleft = !goleft
                    continue
                }
                ichan = this.Buckets[first - leap].Iter()
                
                if first+leap < 159 {
                    goleft = !goleft
                }
            }
            if !goleft {
                if first + leap >= 159 {
                    goleft = !goleft
                    continue
                }
                ichan = this.Buckets[first + leap].Iter()
                
                if first-leap > 0 {
                    goleft = !goleft
                }
            }
            
        }
        closenodes.Push(<-ichan)

    }
    return closenodes
}

func (this *Node) AddNode(node *InNodeDescriptor) bool {

        distance := XOR(this.Nodeid,node.Nodeid)
        no := int(BucketNo(distance))

        
        if this.Buckets[no].Len() >= K  {
            if !(this.Buckets[no].At(0).Session.Ping()) {
                return false
            }
            return true
        } 
        this.Buckets[no].Push(node)
        return true

}


func (this *Node) Bootstrap(port int, known string) bool {
    knownhost,err := net.ResolveUDPAddr(known)
    if err != nil {
        fmt.Printf("E: %s\n", err)
        return false
    }
    random.Seed(time.Nanoseconds())

    //Establish private key
    f, err := os.Open("/home/kris/.godht/private_key", os.O_RDONLY, 0666) 
    if err != nil {
        os.Mkdir("/home/kris/.godht", 0755)
        os.Open("/home/kris/.godht/private_key", os.O_CREAT, 0644)
        f,err = os.Open("/home/kris/.godht/private_key", os.O_WRONLY, 0644)
        if err != nil { fmt.Printf("%s\n", err); return false }
        fmt.Printf("Generating key... \n")
        pk,_ := rsa.GenerateKey(rand.Reader, 768)
        fmt.Printf("Done.. Marshalling\n")
        pkdata := x509.MarshalPKCS1PrivateKey(pk)
        fmt.Printf("Done\n")
        _,err := f.Write(pkdata)
                if err != nil { fmt.Printf("%s\n", err); return false }
        
        f.Close()
        f,err= os.Open("/home/kris/.godht/private_key", os.O_RDONLY, 0666)
                if err != nil { fmt.Printf("%s\n", err); return false }
    }
    fi,err := os.Stat("/home/kris/.godht/private_key")
            if err != nil { fmt.Printf("%s\n", err); return false }
    size := int(fi.Size)
    pkdata := make([]byte, size)
    f.Read(pkdata)

    keypair,err :=  x509.ParsePKCS1PrivateKey(pkdata)
            if err != nil { fmt.Printf("%s\n", err); return false }
    fmt.Printf("Unmarshalled the keypair\n")
    this.Keypair = keypair
    
    
    /*
    //Find out if reachable
    this.Reachable = true
    tmpaddr,_ := net·ResolveUDPAddr("0.0.0.0:5001")
    tmpconn,_ := net.DialUDP("udp", tmpaddr, knownhost)

    m := NewCheckReachability()
    mdata := proto.Marshal(m)
    tmpdata := EncodePacket(mdata, PktType_CHECKREACHABILITY, 0, false, nil)
    tmpconn.Send(tmpdata)
    
    tmpconn.SetReadTimeout(5000000000)
    _,_,err := tmphandler.ReadMsg()
    if err != nil {
        this.Reachable = false
    }
    tmpconn.Close()
    */
    
    
    //Start the listener
    fmt.Printf("Starting the UDPHandler..\n")
    udphandler := NewUDPHandler(port,this)
    go udphandler.Start()
    
    
    //Connect to known host
    fmt.Printf("Connecting to known host\n")
    if err != nil { fmt.Printf("%s\n", err) }
    c := NewUDPSession(knownhost,this,udphandler)
    c.Node = this
    c.NodeIsAdded = false
    go c.Start()
    go c.FindNode(this.Nodeid) //Should be iterative. But not for now
    return true
}

