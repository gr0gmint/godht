# Copyright 2009 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(GOROOT)/src/Make.inc



TARG=dht
GOFILES=\
	datastore.go\
	node.go\
	hotcode.go\
	dht.pb.go\
	jsoninterface.go

include $(GOROOT)/src/Make.pkg
dht.pb.go:
	protoc --go_out=. dht.proto

example: 
	8g example.go
	8l example.8


joe: all install example
