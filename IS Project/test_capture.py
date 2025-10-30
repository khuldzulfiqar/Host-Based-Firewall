from packet_capture import PacketCapture

def log(msg):
    print(msg)

def processor(packet_info):
    # Simple test: Allow all packets
    return True

capture = PacketCapture(log_callback=log)
capture.start_capture(packet_processor=processor)
