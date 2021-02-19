# infer-TCP-flavor
Infer TCP flavor through passive measurement (Reno)

## 方法
在丢包阶段，可以断定统计的acked包都到达发送端（确定cwnd）和未被接收端发出ack的包(确定flightsize) 

## 参考文献
+ S. Jaiswal, G. Iannaccone, C. Diot, J. Kurose, and D. Towsley. Inferring TCP Connection Characteristics Through Passive Measurements. Technical Report RR03-ATL-070121, Sprint ATL, July 2003. 
+ S. Jaiswal, G. Iannaccone, C. Diot, J. Kurose, and D. Towsley. Measurement and classification of out-of-sequence packets in a tier-1 IP backbone. In Proceedings of IEEE Infocom, Mar 2003.
