import requests
import base64

# Define the URL for communication with the server
url = "http://localhost:9998"

# Define the address of the SmartHub
address = "ef0"

# Function to send a POST request with encoded packets
def send_request(packets):
    encoded_packets = [base64.urlsafe_b64encode(packet).decode("utf-8") for packet in packets]
    data = {"packets": encoded_packets}
    print(packets)
    print(data)
    response = requests.post(url, data=data)
    if response.status_code != 200:
        print("Error: Failed to send request to the server.")
        exit(99)
    return response.content.decode("utf-8")

# Function to decode a base64-encoded packet
def decode_packet(encoded_packet):
    decoded_packet = base64.urlsafe_b64decode(encoded_packet)
    return decoded_packet

# Function to calculate the CRC8 checksum
def calculate_crc8(data):
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0x07
            else:
                crc <<= 1
    return crc & 0xFF

# Function to parse the payload of a packet
def parse_payload(payload):
    src = int.from_bytes(payload[0:2], "little")
    dst = int.from_bytes(payload[2:4], "little")
    serial = int.from_bytes(payload[4:6], "little")
    dev_type = payload[6]
    cmd = payload[7]
    cmd_body = payload[8:]
    return src, dst, serial, dev_type, cmd, cmd_body

# Function to encode the payload of a packet
def encode_payload(src, dst, serial, dev_type, cmd, cmd_body):
    payload = bytearray()
    payload.extend(src.to_bytes(2, "little"))
    payload.extend(dst.to_bytes(2, "little"))
    payload.extend(serial.to_bytes(2, "little"))
    payload.append(dev_type)
    payload.append(cmd)
    payload.extend(cmd_body)
    return payload

# Function to handle the WHOISHERE command for SmartHub
def handle_whoishere_smart_hub():
    dev_props = b""
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x01, 0x02, dev_props)
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    response = send_request([packet])
    response_packet = decode_packet(response)
    _, _, _, _, cmd, _ = parse_payload(response_packet)
    if cmd == 0x02:
        print("SmartHub successfully registered in the network.")
    else:
        print("Error: Failed to register SmartHub in the network.")
        exit(99)

# Function to handle the WHOISHERE command for EnvSensor
def handle_whoishere_env_sensor():
    sensors = 0x0F  # Supports all four sensors
    triggers = []
    dev_props = bytearray()
    dev_props.append(sensors)
    for trigger in triggers:
        op_value = (trigger["op"] & 0x01) | ((trigger["value"] & 0x7F) << 1) | ((trigger["sensor"] & 0x03) << 7)
        dev_props.append(op_value)
        dev_props.extend(trigger["name"].encode())
        dev_props.append(0)  # Null terminator
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x02, 0x02, dev_props)
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    response = send_request([packet])
    response_packet = decode_packet(response)
    _, _, _, _, cmd, _ = parse_payload(response_packet)
    if cmd == 0x02:
        print("EnvSensor successfully registered in the network.")
    else:
        print("Error: Failed to register EnvSensor in the network.")
        exit(99)

# Function to handle the WHOISHERE command for Switch
def handle_whoishere_switch():
    dev_props = b""
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x03, 0x02, dev_props)
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    response = send_request([packet])
    response_packet = decode_packet(response)
    _, _, _, _, cmd, _ = parse_payload(response_packet)
    if cmd == 0x02:
        print("Switch successfully registered in the network.")
    else:
        print("Error: Failed to register Switch in the network.")
        exit(99)

# Function to handle the WHOISHERE command for Lamp
def handle_whoishere_lamp():
    dev_props = b""
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x04, 0x02, dev_props)
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    response = send_request([packet])
    response_packet = decode_packet(response)
    _, _, _, _, cmd, _ = parse_payload(response_packet)
    if cmd == 0x02:
        print("Lamp successfully registered in the network.")
    else:
        print("Error: Failed to register Lamp in the network.")
        exit(99)

# Function to handle the WHOISHERE command for Socket
def handle_whoishere_socket():
    dev_props = b""
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x05, 0x02, dev_props)
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    response = send_request([packet])
    response_packet = decode_packet(response)
    _, _, _, _, cmd, _ = parse_payload(response_packet)
    if cmd == 0x02:
        print("Socket successfully registered in the network.")
    else:
        print("Error: Failed to register Socket in the network.")
        exit(99)

# Function to handle the WHOISHERE command for Clock
def handle_whoishere_clock():
    dev_props = b""
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x06, 0x02, dev_props)
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    response = send_request([packet])
    response_packet = decode_packet(response)
    _, _, _, _, cmd, _ = parse_payload(response_packet)
    if cmd == 0x02:
        print("Clock successfully registered in the network.")
    else:
        print("Error: Failed to register Clock in the network.")
        exit(99)

# Function to handle the IAMHERE command for SmartHub
def handle_iamhere_smart_hub():
    dev_props = b""
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x01, 0x02, dev_props)
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    send_request([packet])

# Function to handle the IAMHERE command for EnvSensor
def handle_iamhere_env_sensor():
    dev_props = b""
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x02, 0x02, dev_props)
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    send_request([packet])

# Function to handle the IAMHERE command for Switch
def handle_iamhere_switch():
    dev_props = b""
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x03, 0x02, dev_props)
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    send_request([packet])

# Function to handle the IAMHERE command for Lamp
def handle_iamhere_lamp():
    dev_props = b""
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x04, 0x02, dev_props)
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    send_request([packet])

# Function to handle the IAMHERE command for Socket
def handle_iamhere_socket():
    dev_props = b""
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x05, 0x02, dev_props)
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    send_request([packet])

# Function to handle the IAMHERE command for Clock
def handle_iamhere_clock():
    dev_props = b""
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x06, 0x02, dev_props)
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    send_request([packet])

# Function to handle the GETSTATUS command for SmartHub
def handle_getstatus_smart_hub():
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x01, 0x01, b"")
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    response = send_request([packet])
    response_packet = decode_packet(response)
    _, _, _, _, cmd, cmd_body = parse_payload(response_packet)
    if cmd == 0x04:
        status = cmd_body[0]
        print("SmartHub status:", status)
    else:
        print("Error: Failed to retrieve SmartHub status.")
        exit(99)

# Function to handle the GETSTATUS command for EnvSensor
def handle_getstatus_env_sensor():
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x02, 0x01, b"")
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    response = send_request([packet])
    response_packet = decode_packet(response)
    _, _, _, _, cmd, cmd_body = parse_payload(response_packet)
    if cmd == 0x04:
        values = cmd_body
        print("EnvSensor values:", values)
    else:
        print("Error: Failed to retrieve EnvSensor values.")
        exit(99)

# Function to handle the GETSTATUS command for Switch
def handle_getstatus_switch():
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x03, 0x01, b"")
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    response = send_request([packet])
    response_packet = decode_packet(response)
    _, _, _, _, cmd, cmd_body = parse_payload(response_packet)
    if cmd == 0x04:
        status = cmd_body[0]
        print("Switch status:", status)
    else:
        print("Error: Failed to retrieve Switch status.")
        exit(99)

# Function to handle the GETSTATUS command for Lamp
def handle_getstatus_lamp():
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x04, 0x01, b"")
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    response = send_request([packet])
    response_packet = decode_packet(response)
    _, _, _, _, cmd, cmd_body = parse_payload(response_packet)
    if cmd == 0x04:
        status = cmd_body[0]
        print("Lamp status:", status)
    else:
        print("Error: Failed to retrieve Lamp status.")
        exit(99)

# Function to handle the GETSTATUS command for Socket
def handle_getstatus_socket():
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x05, 0x01, b"")
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    response = send_request([packet])
    response_packet = decode_packet(response)
    _, _, _, _, cmd, cmd_body = parse_payload(response_packet)
    if cmd == 0x04:
        status = cmd_body[0]
        print("Socket status:", status)
    else:
        print("Error: Failed to retrieve Socket status.")
        exit(99)

# Function to handle the SETSTATUS command for Lamp
def handle_setstatus_lamp(status):
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x04, 0x05, bytes([status]))
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    send_request([packet])

# Function to handle the SETSTATUS command for Socket
def handle_setstatus_socket(status):
    cmd_body = encode_payload(0, 0x3FFF, 0, 0x05, 0x05, bytes([status]))
    packet = bytearray()
    packet.append(len(cmd_body) + 2)
    packet.extend(cmd_body)
    packet.append(calculate_crc8(cmd_body))
    send_request([packet])

# Example usage
if __name__ == "__main__":
    # SmartHub
    handle_whoishere_smart_hub()
    handle_iamhere_smart_hub()
    handle_getstatus_smart_hub()

    # EnvSensor
    handle_whoishere_env_sensor()
    handle_iamhere_env_sensor()
    handle_getstatus_env_sensor()

    # Switch
    handle_whoishere_switch()
    handle_iamhere_switch()
    handle_getstatus_switch()

    # Lamp
    handle_whoishere_lamp()
    handle_iamhere_lamp()
    handle_getstatus_lamp()
    handle_setstatus_lamp(1)  # Set Lamp status to ON

    # Socket
    handle_whoishere_socket()
    handle_iamhere_socket()
    handle_getstatus_socket()
    handle_setstatus_socket(1)  # Set Socket status to ON

    # Clock
    handle_iamhere_clock()
