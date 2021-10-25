import pyshark
import iptc
import time, sys


dic = {}
flag = 0
attacker = ""
while flag == 0:
	capture = pyshark.LiveCapture(interface="enp0s8")
	capture.sniff_continuously(10)
	for pkt in capture:
		# print(pkt)
		try:
			tmp = pkt.openflow_v4.field_names
			# print(tmp)
			# print(pkt.openflow_v4.type)
			# print(tmp)
			if pkt.openflow_v4.type == "10":
				# print(pkt)
				src_addr = pkt.ip.src
				src_port = pkt[pkt.transport_layer].srcport
				key_name = src_addr+":"+src_port
				# print(key_name)
				if key_name not in dic:
					dic[key_name] = 1
				else:
					dic[key_name] += 1
				# print(dic)
				# print(dic[key_name])
				if dic[key_name] > 100:
					attacker = key_name
					print("Suspicious traffic from: "+key_name)
					flag = 1
					break
		except:
			pass
	capture.close()
print("attacker is: "+attacker)
# create iptables rule to block attacker
tmp = attacker.split(":")
target_ip = tmp[0]
target_port = tmp[1]
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
rule = iptc.Rule()
rule.src = target_ip
rule.protocol = "tcp"
match = iptc.Match(rule,"tcp")
match.sport = target_port
rule.add_match(match)
target = iptc.Target(rule,"DROP")
rule.target = target
chain.insert_rule(rule)
# show counter values
table = iptc.Table(iptc.Table.FILTER)
chain = iptc.Chain(table,"INPUT")
for rule in chain.rules:
	(packets, bytes) = rule.get_counters()
	print(packets,bytes)
sys.stdout.flush()
time.sleep(3)
table.refresh()
for rule in chain.rules:
        (packets, bytes) = rule.get_counters()
        print(packets,bytes)

exit()
