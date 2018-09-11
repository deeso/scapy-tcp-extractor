
## Summary

This code implements TCP stream reassembly using _scapy_ packets.  It
implements a TCP state machine, and then groups related packets.  After
grouping streams, the data in the streams is concatenated.

This code is old, and I am not entirely sure it's not implemented else where.

## Usage

To use it from IPython, I perform the following:

```
filename = "../../infected-traffic.pcap"
from scapy_tcp.stream_extractor import TCPStreamExtractor
from analyst_environment.pcaps import *
from analyst_environment.environment_setup import *
tse = TCPStreamExtractor(filename)

# stream keys 'SRC:SPORT ==> DST:DPORT' 
#        ===> {SPORT:bytes(CLIENT_STREAM), DPORT:bytes(SERVER_STREAM)}

data_streams = tse.get_streams()
```


## Background 

This is research quality code, included in this package is code 
perform TCP Stream extraction, and there is some proposed starts
on how to perform the auto-matic send and receive on TCP sessions.
The automagic stuff does not work yet, but it is left for anyone 
who would like to see how that process might work.

The code that does work is in tcp_sm.py, tcp_stream.py, and 
tcp_stream_extractor.py.  The tcp_sm file holds the TCPState class,
and this class is used to identify handshakes, maintain established
connections, and then identify when the stream gets closd.  The code
should be self documenting, but there may be some confusion about how
the TCP state transitions happen.  I read the spec, wrote some code, 
and then checked with some sample application streams.

The code in the tcp_stream is dedicated to the TCPStream class.  This 
class is is used to track the established streams, and by tracking, I 
mean collect all the packets and order them by timestamp.  There some
interesting things to note.  First, if we are processing a large file,
say like on the order of GBs, we can not maintain all the packets of all
the streams, so the code will allow us to write out packets and flows in
an incremental nature.  There are writers for the pcap, couchdb, and then
a summary of flows.  My summaries were very specific, so if you want to
adjust or specalize summaries, this would be a good place to do it.

The final element we will discuss is the TCPStreamExtractor class, which 
is found in the tcp_stream_extractor class.  This class is where ALL the 
magic happens.  This class performs the writing of classes out when they 
are stale (e.g. no packets after some timeout value).  I use a low timeout
value, which may or may not be appropriate, but it works for my neeeds.
There is also a clean-up thread that runs from this class, and it is
used to prune out the stale streams, and write them out to file.   This 
thread will only run when TCPStreamExtractor.run is called to run 
independently.  Alternatively, the user can control the class with the 
TCPStreamExtractor.next call, rather than running unsupervised.  

The only required software for this code is Scapy.  


Some future work for this code is to create TCP Stream reassembly using 
pynids, and then adding some functionality that performs live capture.  
The live capture addition should be trivial either by extending the 
TCPStreamExtractor and overriding the TCPStreamExtractor.next method.  
This is the primary driver for the code.  I did not have a chance to add
this because I had other obligations to fullfill before I could implement
this feature.  

As for the Pynids, there is currently no way to feed packets from Scapy 
to pynids, and this feature would requires some C-programming.  The way I
implement this feature is add some APIs to the Pynids nidsmodule.c that 
would take a string, convert it to a packet, and then pass it to the 
processing engine.  However, this approach is based on a cursory analysis
of the code.





Happy hacking.

-- Adam
