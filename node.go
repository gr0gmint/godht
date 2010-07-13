package dht


import . "container/vector"
import "net"
import "os"
import "crypto/rsa"
import "crypto/x509"
import "crypto/rand"
import "crypto/sha1"
import "crypto/hmac"
import "crypto/aes"
import "crypto/block"
import random "rand"
import "time"
import "encoding/binary"
import "bytes"
import "goprotobuf.googlecode.com/hg/proto"
import "fmt"
import "big"
import "sort"
import "io"

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
    KEYSIZE = 16

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

type streamsyn struct {
    session *UDPSession
    handler *StreamHandler
    data []byte
}
type StreamListener struct {
    Ports map[int](chan streamsyn)
}
func NewStreamListener() *StreamListener {
    s := new(StreamDealer)
    s.Ports = make(map[int](chan streamsyn))
}

type StreamHandler struct {
    
}

type Atom struct {
    HotRoutine
}
func NewAtom() *Atom {
    a := new(Atom)
    go a.HotStart()
    return a
}
func (this *Atom) Do(joe func() ) {
    h := NewHot(func(shared map[string]interface{}){
        self := shared["self"].(*GenericHot)
        joe()
        self.Answer<-true
    })
    this.QueryHot(h)
    <-h.Answer
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
    StreamListener *StreamListener
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
    IdMap map[int32]chan hdr_n_data
    Default chan hdr_n_data
    NeedToSendDesc bool //If the repicient needs the publickey
    NodeIsAdded bool //If the node is added to bucket
    First bool //Keep track of the first packet sent
    NeedToSendKey bool
    EncryptKey []byte
    DecryptKey []byte
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

func ReadAll (r io.Reader, b []byte)  {
    l := len(b)
    total := 0
    var n int
    for {
        if l-total < KEYSIZE {
            return
        } else {
            n, _ = r.Read(b[total:total+KEYSIZE])
        }
        total += n
        if n == 0 { break }

    }
}
func WriteAll (w io.Writer, b []byte) {
    l := len(b)
    total := 0
    var n int
    for {
        if l-total < KEYSIZE  {
            joe := [16]byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
            nb := bytes.NewBuffer(b[total:])
            nb.Write(joe[0:16-(l-total)])
            w.Write(nb.Bytes())
            break
        } else {
            n, _ = w.Write(b[total:total+KEYSIZE])
        }
        if n == 0 { break }
        total += n
    }
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
    var chdrlen uint32
    var hdrlen uint32
    var datalen uint32
    if len(data) < 8 {
        fmt.Printf("len(data) < 8\n")
        return nil,data,os.ENOMEM
    }
    err := binary.Read(data[0:4], binary.BigEndian, &chdrlen)
        if err != nil { return nil,nil,err }
    payload := data[4+chdrlen:]
    fmt.Printf("Length of payload = %d\n", len(payload))
        


    fmt.Printf("chdrlen = %d, len(payload) = %d\n", chdrlen, len(payload))
    cryptoheader := NewCryptoHeader()
    err = proto.Unmarshal(data[4:4+chdrlen], cryptoheader)
    if err != nil {
        fmt.Printf("Returning error\n")
        return nil,data,err
    }
    if *cryptoheader.Needkey {
        fmt.Printf("Recipient needs key\n")
        this.NeedToSendKey = true
    }
    //VERIFY AND/OR DECRYPT
    if cryptoheader.Key != nil {
        h := sha1.New()
        this.DecryptKey, err = rsa.DecryptOAEP(h,rand.Reader, this.Node.Keypair, cryptoheader.Key, &[...]byte("GONUTS")) 
        fmt.Printf("DecryptKey = %x\n", this.DecryptKey)
    }
    
    if *cryptoheader.Isencrypted && this.DecryptKey == nil {
        return nil,nil,os.NewError("Has no decryptionkey")
    }
    if  cryptoheader.Hmac != nil && this.DecryptKey != nil {
        fmt.Printf("Payload: %s\n", payload)
        hm := hmac.NewSHA1(this.DecryptKey)
        hm.Write(payload)
        sum := hm.Sum()
        fmt.Printf("HMAC? %x =?= %x\n", cryptoheader.Hmac, sum)
        if bytes.Compare(cryptoheader.Hmac, sum) == 0 {
            fmt.Printf("HMAC verified\n")
            
        } else {
            return nil,nil,os.NewError("HMAC didn't verify\n")
        }
    }
    if *cryptoheader.Isencrypted {
        fmt.Printf("Packet is encrypted! Decrypting!\n")
        cipher,_ := aes.NewCipher(this.DecryptKey)
        ciphertext := bytes.NewBuffer(payload)
        cbc := block.NewCBCDecrypter(cipher, this.DecryptKey, ciphertext)
        fmt.Printf("%x\n", this.DecryptKey)
        ReadAll(cbc,payload)
    }

    err = binary.Read(payload[0:4], binary.BigEndian, &hdrlen)
        if err != nil { return nil,data,err }
    err = binary.Read(payload[4:8], binary.BigEndian, &datalen)
        if err != nil { return nil,data,err }
    fmt.Printf("hdrlen = %d, datalen = %d, len(payload) = %d\n", hdrlen, datalen,len(payload))
    if !(hdrlen < 2048 && datalen <= 8096 ) {
        fmt.Printf("Packet too big!\n")
        return nil,data,os.ENOMEM
    }
    hdrdata := payload[8:8+hdrlen]
    newdata := payload[8+hdrlen:8+hdrlen+datalen]
    header := NewHeader()
    
    err = proto.Unmarshal(hdrdata, header)
    if err != nil {
        fmt.Printf("Header ···· Returning error\n")
        return nil,nil,err
    }
    //Verify timestamp
    difference := *header.Timestamp - time.Seconds()
    if difference < -(5*60) || difference > (5*60) {
        return nil,nil,os.NewError("Timestamp is too far off\n")
    }
    
    newdata2 := make(Buf, datalen)
    copy(newdata2,newdata)
    
    return header, newdata2,nil
}
 
func (this *UDPSession) EncodePacket(data []byte, t,id,part int32, ishmac,encrypted bool) []byte {
        newt := NewPktType(t)
  
        
        header := NewHeader()
        header.Type = newt
        header.Msgid = proto.Int32(id)
        header.Part = proto.Int32(part)
        header.Timestamp = proto.Int64(time.Seconds())
        fmt.Printf("NodeIsAdded = %t\n", this.NodeIsAdded)
        header.Knowsyou = proto.Bool(this.NodeIsAdded)
        if this.NeedToSendDesc {
            //Include publickey
            fmt.Printf("NeedToSendDesc is set!\n")
            header.From = this.Node.Descriptor()

        }
        if this.RecpNode == nil {
            encrypted = false
        }
        hdrdata,err := proto.Marshal(header)
        if err != nil {
            fmt.Printf("%s\n", err)
            return nil
        }
        
        hdrlen := uint32(len(hdrdata))
        datalen :=  uint32(len(data))
        
        p := bytes.NewBufferString("")
        binary.Write(p, binary.BigEndian, [2]uint32{hdrlen,datalen})
        p.Write(hdrdata)
        p.Write(data)
        payload := p.Bytes()
        fmt.Printf("len(payload) before crypto = %d\n", len(payload))
        
        cryptoheader := NewCryptoHeader()
        cryptoheader.Isencrypted = proto.Bool(encrypted)
        if this.DecryptKey == nil {
            cryptoheader.Needkey = proto.Bool(true)
        } else {
            cryptoheader.Needkey = proto.Bool(false)
         }
        if this.RecpNode != nil {
            if this.EncryptKey == nil {
                this.EncryptKey = make([]byte, KEYSIZE)
                rand.Reader.Read(this.EncryptKey)
                fmt.Printf("EncryptKey = %x\n", this.EncryptKey)
            }
            
            if this.NeedToSendKey { //Recipient hasn't got EncryptKey yet
                h := sha1.New()
                fmt.Printf("Encrypting key!\n")
                cryptoheader.Key, err = rsa.EncryptOAEP(h, rand.Reader, this.RecpNode.Publickey, this.EncryptKey, &[...]byte("GONUTS"))
                this.NeedToSendKey = false
            }
            
            if encrypted {
                fmt.Printf("Ciphertext with key: %x\n", this.EncryptKey)
                cipher,_ := aes.NewCipher(this.EncryptKey)
                ciphertext := bytes.NewBufferString("")
                cbc := block.NewCBCEncrypter(cipher, this.EncryptKey, ciphertext)
                WriteAll(cbc,payload)
                payload = ciphertext.Bytes()
            }
            if ishmac {

                hm := hmac.NewSHA1(this.EncryptKey)
                hm.Write(payload)
                cryptoheader.Hmac = hm.Sum()

                                fmt.Printf("HMAC'ing: %x\n", cryptoheader.Hmac)
            }

        }
        fmt.Printf("len(payload) after crypto = %d\n", len(payload))
        chdrdata,err := proto.Marshal(cryptoheader)
        
        if err != nil {
            fmt.Printf("%s\n", err)
            return nil
        }   
        
        
        chdrlen := uint32(len(chdrdata))
        fmt.Printf("Sending with: chdrlen = %d, hdrlen = %d, datalen = %d\n", chdrlen, hdrlen, datalen)
        buffer := make(Buf, 4+chdrlen+uint32(len(payload)))
        binary.Write(buffer, binary.BigEndian, [1]uint32{chdrlen})

        copy(buffer[4:],chdrdata)
        copy(buffer[4+chdrlen:], payload)
        return buffer
}



func NewUDPSession(raddr *net.UDPAddr, node *Node, udphandler *UDPHandler) *UDPSession {
    c := new(UDPSession)
    c.RAddr =  raddr
    c.Handler = udphandler
    c.Node = node
    c.First = true
    c.NeedToSendKey = true
    if c.Handler.FromMap[raddr.String()] == nil {
    c.Handler.FromMap[raddr.String()] = make(chan Buf)
    }
    c.IdMap = make(map[int32]chan hdr_n_data)
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

func (this *UDPSession) _handleStore(header *Header, data []byte) {
    v := bytes.NewBufferString("")
    p := NewStore()
    var i int32
    fmt.Printf("_handleStore\n")
    for i =1; true; i++ {
        err := proto.Unmarshal(data,p)
        
        if err != nil { 
            fmt.Printf("err: %s\n", err)
            answer := NewAnswerOk()
            answer.Ok = proto.Bool(false)
            adata,_ := proto.Marshal(answer)
            this.Send(adata, PktType_ANSWEROK, *header.Msgid, i, false,false)
            break
        }
        v.Write(p.Value)
        answer := NewAnswerOk()
        answer.Ok = proto.Bool(true)
        adata,_ := proto.Marshal(answer)
        this.Send(adata, PktType_ANSWEROK, *header.Msgid, i, false,false)
        

        if *p.Ismore {
            header,data = this.Read(*header.Msgid, 0)
            if *header.Part != i+1 { break }
            continue
        } else {
            fmt.Printf("Setting a value\n")
            this.Node.Data.Set(p.Key, v)
            break
        }
    }
      
}

func (this *UDPSession) Start() {
    fmt.Printf("UDPSession started\n")
    this.Default = make(chan hdr_n_data)
    saddr := this.RAddr.String()
    if this.Handler.FromMap[saddr] == nil {
        this.Handler.FromMap[saddr] = make (chan Buf)
    }
    packetchan := this.Handler.FromMap[saddr]
    go func() {
        for {
            packet := <-packetchan
            if packet == nil {fmt.Printf("Error reading from UDPHandler"); break }
            header,data,err := this.DecodePacket(packet)
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
                    this.IdMap[*header.Msgid] = make(chan hdr_n_data)
                }
                go func() { fmt.Printf("this.IdMap[%d]<-packet\n", *header.Msgid); this.IdMap[*header.Msgid]<-hdr_n_data{header,data}}()
            } else {
                go func() { this.Default <- hdr_n_data{header,data} }()
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
                go this._handleStore(header,data)
            case PktType_FINDNODE:
                p := NewFindNode()
                err := proto.Unmarshal(data,p)
                if err != nil {
                    fmt.Printf("E: %s\n", err)
                    break
                }
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
                    fmt.Printf("Sending back this value: %s\n", answer.Value)
                }
                adata,err := proto.Marshal(answer)
                if err != nil { fmt.Printf("E: %s\n", err) }
                this.Send(adata, PktType_ANSWERNODES, *header.Msgid,1,true,true)
            case PktType_PING:
                a := NewPong()
                adata,err := proto.Marshal(a)
                if err != nil  {fmt.Printf("E: %s\n", err)}
                this.Send(adata, PktType_ANSWERPONG,*header.Msgid, 1, true,false)
                
            case PktType_STREAM:
                s := NewStream()
                err := proto.Unmarshal(data, s)
                if err != nil {
                    go this._handleStream(header,s)
                }
        }
    }
    
}

func (this *UDPSession) _handleStream(header *Header, s *Stream) {
    port := *s.Port
    handler := NewStreamHandler()
    this.Node.StreamListener.AddStream(port,handler, this)
    
}


func (this *StreamListener) AddStream(port int, handler *StreamHandler, session *UDPSession) {
    ch, ok := this.Ports
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
        var data hdr_n_data
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
  
        } else {
            if d,ok := this.IdMap[msgid]; !ok || d == nil { fmt.Printf("make(chan Buf)\n"); this.IdMap[msgid] = make(chan hdr_n_data) }
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
        }
                  if this.RecpNode != nil {
            this.Node.MoveKeyToTop(this.RecpNode.Nodeid) //There is activity, so we move the nodeid to the top of the bucket
            }
            header := data.header
            mdata := data.data
            if header == nil {
                return nil,nil
            }
            //Set the NeedToSendDesc flag, if "Knowsyou" is set in packet
            fmt.Printf("header Knowsyou = %t\n", *header.Knowsyou)
            if *header.Knowsyou {fmt.Printf("Setting NeedToSendDesc\n"); this.NeedToSendDesc = false } else { this.NeedToSendDesc = true }
              //If this is some of the first packets received  - needs perhaps to be added to bucket
              if !this.NodeIsAdded { this.AddRecpNode(header.From) }
              
              return header,mdata
        /*
    })
    this.QueryHot(h)
    *//*
    answer:=(<-h.Answer).(hdr_n_data)
   return answer.header,answer.data
   */
   
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
    this.Send(ping_data, PktType_PING, msgid, 0, true,false)
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
            this.Node.AddNode(innode)
            nodes.Push(innode)
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

func (this *UDPSession) Store(key Key, value io.Reader) bool {
    msgid := NewMsgId()
    b := make([]byte, 3000)
    for i:= 0; true; i++ {
        n,err := value.Read(b)
        if n != 0 {
            m := NewStore()
            m.Key = key
            m.Value = b[0:n]
            if err != nil { m.Ismore = proto.Bool(false) } else { m.Ismore = proto.Bool(false) }
            mdata,_ := proto.Marshal(m)
            this.Send(mdata,PktType_STORE, msgid, int32(i),true,false)
            if !this.IsAccepted(msgid) {
                return false
            }
        }
        if err != nil {
        break
        }
    }
    fmt.Printf("I sent the store command\n")
    return true
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
    n.StreamListener := NewStreamListener()
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






/*
//Internal
func (this *Node) _iterFindNode(session *UDPSession,  
                                key Key, 
                                closest Key, 
                                shortlist *Bucket,
                                cancel *bool, 
                                alreadyAsked *Bucket, 
                                sync *Atom                        ) {
    var nodes *Bucket

    
    
    if *cancel { return }
    
    
    nodes = session.FindNode(key)
    sync.Do(func() {
        shortlist.Push(session.RecpNode)
        
    })
    if nodes == nil { return }
    ich := nodes.Iter()
    for {
        if *cancel { return }
        if closed(ich) { break }
        inode:=<-ich
        if inode == nil {
            break
        }
        
        
        if bytes.Compare(inode.Nodeid,this.Nodeid) == 0 { //If this is ourself
            continue
        }
        
        

        if already {
            continue
        }
        closer := false
         sync.Do(func() {

            
                    if XOR(inode.Nodeid, key).Less( XOR(closest, key) ) {
                        closer = true 
                        copy(closest, inode.Nodeid)
                        shortlist.Push(inode)
                    }
                })
        if closer {
                fmt.Printf("Asking %x for peers\n", keytobyte(inode.Nodeid))
        this._iterFindNode(inode.Session, key,  closest, shortlist, cancel, alreadyAsked, sync)
        }
 
        newnodes := inode.Session.FindNode(key)
        
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
                ch <- newnodes
                return
            }
        }        
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
    }
}
      */
  



func (this *Node) IterativeFindNode(key Key) *Bucket {
    hasnodes := this.FindCloseNodes(key)
    
    cancel := new(bool)
    *cancel = false
    
    ch := make(chan bool)
    done := make (chan bool)

    async := NewAtom()
    var shortlist *Bucket
    nodelist := NewBucket(this)
    closest := make(Key, 20)
    alreadyAsked := NewBucket(this)
    shortlist=hasnodes
    fmt.Printf("Length of shortlist = %d\n", shortlist.Len())
     at := 0
    for {

    go func() {
        for i:= at; i < shortlist.Len()  && i < at+Alpha; i++ {

                ic := i
                go func() {
                    defer func() {ch <- false; at++}()
                    fmt.Printf("hasnodes.At(%d)\n", ic)
                    inode :=  shortlist.At(ic)
                    if inode != nil {
                        already := false
                        j := alreadyAsked.Iter()
                        async.Do(func() {
                            for {

                                if closed(j) {break}
                                m := <-j
                                if m == nil {break}
                                
                                if bytes.Compare(m.Nodeid, inode.Nodeid) == 0 {already=true; break}
                            }
                           if !already {
                                alreadyAsked.Push(inode)
                            }
                            
                                donotadd := false
                                    if bytes.Compare(inode.Nodeid, this.Nodeid) == 0 { donotadd = true }
                                    if !donotadd {
                                        nodelist.Push(inode)
                                }
                            
                        })
                        if !already {
                            fmt.Printf("Asking peer %x\n", keytobyte(inode.Nodeid))
                            nodes := inode.Session.FindNode(key)
                                                        fmt.Printf("Done Asking\n")
                            closer := false
                            if nodes == nil {return }
                                     c :=  nodes.Iter()
                            async.Do(func() { 

                                for {

                                    if closed(c) {break}
                                    n := <-c
                                    if n == nil {break}
                                    
                                    donotadd := false
                                    if bytes.Compare(n.Nodeid, this.Nodeid) == 0 { donotadd = true }
                                    for k := 0; k < nodelist.Len(); k++ {
                                        if bytes.Compare(n.Nodeid, nodelist.At(k).Nodeid) == 0   { donotadd = true; }
                                    }
                                    if !donotadd {
                                        nodelist.Push(n)
                                    }
                                    if XOR(n.Nodeid, key).Less( XOR(closest, key) )  {
                                        closer =true
                                    }
                                }
                            })
                            fmt.Printf("Back from async\n")
                            if closer {
                                ch <- true
                            }
                        }

                    }
                }()
        }
        closer := false
        for i:= 0; i < shortlist.Len()  && i < Alpha; i++ {
            fmt.Printf("i = %d\n", i)
            a := <-ch
            if a {closer = true}
        }
        fmt.Printf("done <-closer\n")
        done <-closer
      }()
    fmt.Printf("waiting\n")
    a := <-done
    fmt.Printf("done waiting\n")
    if a { 
        nodelist.SetSortKey(key)
        sort.Sort(nodelist)
        shortlist := NewBucket(this)
        for i := 0; i < 20 && i < nodelist.Len(); i++ {

        shortlist.Push(nodelist.At(i))

        }
        at = 0
        continue
    } else if at+Alpha > shortlist.Len() {
        break
    } else {
       at += Alpha
       fmt.Print("Continuing ... shortlist.Len() = %d\n", shortlist.Len())
       continue
    }
    }
    l := nodelist.Len()
        nodelist.SetSortKey(key)
        sort.Sort(nodelist)
    if l > 20 {
    nodelist.Cut(20,l-1)
    }
    fmt.Printf("Returning nodelist with length of=%d\n", nodelist.Len())
    return nodelist
}


func (this *Node) IterativeFindValue(key Key) (*Bucket, []byte) {
    hasnodes := this.FindCloseNodes(key)
    
    cancel := new(bool)
    *cancel = false
    
    ch := make(chan bool)
    done := make (chan bool)
    

    async := NewAtom()
    var shortlist *Bucket
    nodelist := NewBucket(this)
    closest := make(Key, 20)
    alreadyAsked := NewBucket(this)
    var value []byte
    shortlist=hasnodes
    fmt.Printf("Length of shortlist = %d\n", shortlist.Len())
     at := 0
    for {

    go func() {
        for i:= at; i < shortlist.Len()  && i < at+Alpha; i++ {

                ic := i
                go func() {
                    defer func() {ch <- false; at++}()
                    fmt.Printf("hasnodes.At(%d)\n", ic)
                    inode :=  shortlist.At(ic)
                    if inode != nil {
                        already := false
                        j := alreadyAsked.Iter()
                        async.Do(func() {
                            for {

                                if closed(j) {break}
                                m := <-j
                                if m == nil {break}
                                
                                if bytes.Compare(m.Nodeid, inode.Nodeid) == 0 {already=true; break}
                            }
                           if !already {
                                alreadyAsked.Push(inode)
                                
                            }
                        })
                        if !already {
                            fmt.Printf("Asking peer %x\n", keytobyte(inode.Nodeid))
                            nodes,v := inode.Session.FindValue(key)
                                                        fmt.Printf("Done Asking\n")
                            if v != nil {
                               value = v
                               ch <-true
                               done <- true
                               return
                               
                            }
                            closer := false
                            if nodes == nil {return }
                                     c :=  nodes.Iter()
                            async.Do(func() { 

                                for {

                                    if closed(c) {break}
                                    n := <-c
                                    if n == nil {break}
                                    
                                    donotadd := false
                                    if bytes.Compare(n.Nodeid, this.Nodeid) == 0 { donotadd = true }
                                    for k := 0; k < nodelist.Len(); k++ {
                                        if bytes.Compare(n.Nodeid, nodelist.At(k).Nodeid) == 0   { donotadd = true; }
                                    }
                                    if !donotadd {
                                        nodelist.Push(n)
                                    }
                                    if XOR(n.Nodeid, key).Less( XOR(closest, key) )  {
                                        closer =true
                                    }
                                }
                            })
                            fmt.Printf("Back from async\n")
                            if closer {
                                ch <- true
                            }
                        }

                    }
                }()
        }
        closer := false
        for i:= 0; i < shortlist.Len()  && i < Alpha; i++ {
            fmt.Printf("i = %d\n", i)
            a := <-ch
            if a {closer = true}
        }
        fmt.Printf("done <-closer\n")
        done <-closer
      }()
    fmt.Printf("waiting\n")
    a := <-done
    
    fmt.Printf("done waiting\n")
    if a { 
        nodelist.SetSortKey(key)
        sort.Sort(nodelist)
        shortlist := NewBucket(this)
        for i := 0; i < 20 && i < nodelist.Len(); i++ {

        shortlist.Push(nodelist.At(i))

        }
        at = 0
        continue
    } else if at+Alpha > shortlist.Len() {
        break
    } else {
       at += Alpha
       fmt.Print("Continuing ... shortlist.Len() = %d\n", shortlist.Len())
       continue
    }
    }
    l := nodelist.Len()
        nodelist.SetSortKey(key)
        sort.Sort(nodelist)
    if l > 20 {
    nodelist.Cut(20,l-1)
    }
    fmt.Printf("Returning nodelist with length of=%d\n", nodelist.Len())
    return nodelist,value
}



type v_answer struct {
    nodes *Bucket
    value []byte
}



func (this *Node) IterativeStore(key Key, value io.Reader) {
    closenodes := this.IterativeFindNode(key)
    fmt.Printf("back from iterativefindnode\n")
    ch := closenodes.Iter()
    for {
        if closed(ch) { break }
        m := <-ch
        if m == nil {break}
        fmt.Printf("Trying to STORE on %s\n", m.Session.RAddr)
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
func bytetobuf(b []byte) Buf {
    return b
}
