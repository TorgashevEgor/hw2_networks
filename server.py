import socket
import struct


class DNSValidationError(Exception):
    def __init__(self, rcode: int):
        self.rcode = rcode
        super().__init__(f"DNS validation failed with RCODE {rcode}")


class DNSRequest:
    def __init__(self, raw_data: bytes):
        self.raw_data = raw_data
        if len(raw_data) < 12:
            raise DNSValidationError(1)

        header = struct.unpack("!HHHHHH", raw_data[:12])
        self.id = header[0]
        flags = header[1]
        self.qdcount = header[2]

        self.qr = (flags >> 15) & 1
        self.opcode = (flags >> 11) & 0xF
        self.rd = (flags >> 8) & 1

        if self.qr != 0:
            raise DNSValidationError(0)
        if self.opcode != 0:
            raise DNSValidationError(4)
        if self.qdcount != 1:
            raise DNSValidationError(1)

        self.domain_name, name_end_offset = self._parse_domain_name(raw_data, 12)

        self.qtype, self.qclass = struct.unpack("!HH", raw_data[name_end_offset:name_end_offset + 4])
        self.question_end = name_end_offset + 4

        if self.qtype != 1 or self.qclass != 1:
            raise DNSValidationError(4)

        self.question_section = raw_data[12:self.question_end]

    @staticmethod
    def _parse_domain_name(data: bytes, offset: int):
        parts = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0:
                offset += 2
                break
            offset += 1
            parts.append(data[offset:offset + length].decode("ascii", errors="ignore"))
            offset += length
        return ".".join(parts), offset


class DNSServer:
    ROOT_DNS_IP = "199.9.14.201"
    PORT = 53

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.PORT))

    def run(self):
        print(f"DNS server started on {self.host}:{self.PORT}")
        while True:
            try:
                packet, client_addr = self.socket.recvfrom(512)
                if len(packet) < 12:
                    continue

                try:
                    request = DNSRequest(packet)
                    print(f"-> Query '{request.domain_name}' from {client_addr[0]}")

                    resolved_ip = self._iterative_resolve(packet, request.domain_name)

                    if resolved_ip:
                        response = self._create_success_response(request, resolved_ip)
                        self.socket.sendto(response, client_addr)
                        print(f"<- Resolved '{request.domain_name}' -> {resolved_ip}")
                    else:
                        response = self._create_error_response(request.id, request.rd, 2)  # SERVFAIL
                        self.socket.sendto(response, client_addr)
                        print(f"! Resolution failed for '{request.domain_name}', sent SERVFAIL")

                except DNSValidationError as e:
                    try:
                        req_id = struct.unpack("!H", packet[:2])[0]
                        rd = (struct.unpack("!H", packet[2:4])[0] >> 8) & 1
                        print(f"! Validation error (RCODE {e.rcode}) from {client_addr[0]}")
                        if e.rcode != 0:
                            error_response = self._create_error_response(req_id, rd, e.rcode)
                            self.socket.sendto(error_response, client_addr)
                    except Exception:
                        pass
                except Exception as err:
                    print(f"! Packet processing error: {err}")

            except Exception as outer_err:
                print(f"! Socket error: {outer_err}")

    def _iterative_resolve(self, query_packet: bytes, domain_name: str):
        current_server = self.ROOT_DNS_IP
        print(f"Starting iterative resolution for {domain_name} from root {current_server}")

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver_socket:
            resolver_socket.settimeout(2.5)
            for step in range(1, 16):
                try:
                    resolver_socket.sendto(query_packet, (current_server, 53))
                    response_data, _ = resolver_socket.recvfrom(512)

                    ip, next_ns = self._parse_remote_response(response_data)
                    if ip:
                        return ip
                    if next_ns:
                        current_server = next_ns
                    else:
                        break
                except socket.timeout:
                    print(f"Timeout reaching server {current_server}")
                    break
        return None

    @staticmethod
    def _parse_remote_response(data: bytes):
        try:
            _, flags, q_count, an_count, ns_count, ar_count = struct.unpack("!HHHHHH", data[:12])
            if flags & 0x000F:
                return None, None

            offset = 12
            for _ in range(q_count):
                offset = DNSServer._skip_name(data, offset)
                offset += 4

            for _ in range(an_count):
                offset = DNSServer._skip_name(data, offset)
                rtype, rclass, _, rlen = struct.unpack("!HHIH", data[offset:offset + 10])
                offset += 10
                if rtype == 1 and rclass == 1 and rlen == 4:
                    return socket.inet_ntoa(data[offset:offset + 4]), None
                offset += rlen

            for _ in range(ns_count):
                offset = DNSServer._skip_name(data, offset)
                _, _, _, rlen = struct.unpack("!HHIH", data[offset:offset + 10])
                offset += 10 + rlen

            for _ in range(ar_count):
                offset = DNSServer._skip_name(data, offset)
                rtype, rclass, _, rlen = struct.unpack("!HHIH", data[offset:offset + 10])
                offset += 10
                if rtype == 1 and rclass == 1 and rlen == 4:
                    return None, socket.inet_ntoa(data[offset:offset + 4])
                offset += rlen

        except Exception:
            pass
        return None, None

    @staticmethod
    def _skip_name(data: bytes, offset: int):
        while True:
            length = data[offset]
            if length == 0:
                return offset + 1
            if length & 0xC0:
                return offset + 2
            offset += 1 + length

    @staticmethod
    def _create_success_response(request: DNSRequest, ip_str: str) -> bytes:
        flags = 0x8180 if request.rd else 0x8000
        header = struct.pack("!HHHHHH", request.id, flags, 1, 1, 0, 0)
        ip_bytes = socket.inet_aton(ip_str)
        answer = request.question_section[-4:] + struct.pack("!HHIH", 1, 1, 300, 4) + ip_bytes
        return header + request.question_section + answer

    @staticmethod
    def _create_error_response(req_id: int, rd: int, rcode: int) -> bytes:
        flags = 0x8000 | (rd << 8) | (rcode & 0xF)
        return struct.pack("!HHHHHH", req_id, flags, 0, 0, 0, 0)


if __name__ == "__main__":
    server = DNSServer()
    server.run()