import pyshark



flag = 0
while flag == 0:
	filename = "capture.pcap"
	output = open(filename,"w")
	time = 30
	capture = pyshark.LiveCapture(interface="eth0",output_file=filename)
	capture.sniff(timeout=time)
	output.close()
	cap = pyshark.FileCapture('capture.pcap')
	for pkt in cap:
		try:
			if 'of13_packet_in_data' in pkt.of.field_names:
				dst_addr = pkt.ip.dst
				dst_port = pkt[pkt.transport_layer].dstport
				print(dst_addr,dst_port)
				print(pkt)
				flag = 1
				break
		except:
			pass
exit()


