all:  
	gcc mypcap.c p3.c -o p3
	@echo      

test1: 
	./p3       test1_PING_notMine.pcap      student_test1_output.pcap      arp.dat
	diff  -s   test1_output.pcap            student_test1_output.pcap      
	@echo      

test2: 
	./p3       test2_ARP_unicast.pcap       student_test2_output.pcap      arp.dat
	diff  -s   test2_output.pcap            student_test2_output.pcap      
	@echo

test3: 
	./p3       test3_ARP_broadcast.pcap     student_test3_output.pcap      arp.dat
	diff  -s   test3_output.pcap            student_test3_output.pcap      
	@echo      

test4: 
	./p3       test4_ARP_notMine.pcap       student_test4_output.pcap      arp.dat
	diff  -s   test4_output.pcap            student_test4_output.pcap      
	@echo      

test5: 
	./p3       test5_PING_mine.pcap         student_test5_output.pcap      arp.dat
	diff  -s   test5_output.pcap            student_test5_output.pcap      
	@echo      

test6: 
	./p3       test6_input.pcap             student_test6_output.pcap      arp.dat
	diff  -s   test6_output.pcap            student_test6_output.pcap      
	@echo      

clean:
	rm -f p3   student_test?_output.pcap 
	@echo      
