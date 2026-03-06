import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class DNSClient {

	// DNS always runs on UDP port 53
	private static final int DNS_PORT = 53;

	// DNS record types we support
	private static final int TYPE_A = 1; // IPv4 address
	private static final int TYPE_NS = 2; // Name server
	private static final int TYPE_CNAME = 5; // Canonical name (alias)

	// Internet class (almost all DNS queries use IN)
	private static final int CLASS_IN = 1;

	public static void main(String[] args) {

		// Program expects hostname and optional DNS server
		if (args.length < 1 || args.length > 2) {
			System.out.println("Usage: java DNSClient <hostname> [dnsServerIp]");
			return;
		}

		String hostname = args[0];

		// Default DNS server if one isn't specified
		String dnsServerIp = (args.length == 2) ? args[1] : "8.8.8.8";

		try {
			// Build DNS query packet
			byte[] query = buildQuery(hostname);

			// Create UDP socket
			DatagramSocket socket = new DatagramSocket();

			// Avoid blocking forever waiting for reply
			socket.setSoTimeout(3000);

			// Convert DNS server string to address
			InetAddress serverAddr = InetAddress.getByName(dnsServerIp);

			// Create UDP packet containing DNS query
			DatagramPacket request = new DatagramPacket(query, query.length, serverAddr, DNS_PORT);

			// Send DNS query
			socket.send(request);

			// Prepare buffer for response
			byte[] buffer = new byte[2048];

			DatagramPacket response = new DatagramPacket(buffer, buffer.length);

			// Receive response from DNS server
			socket.receive(response);

			socket.close();

			// Copy only the actual response bytes
			byte[] message = new byte[response.getLength()];
			System.arraycopy(response.getData(), 0, message, 0, response.getLength());

			// Parse and print the DNS response
			parseAndPrintResponse(message);

		} catch (Exception e) {
			System.out.println("Error: " + e.getMessage());
		}
	}

	/**
	 * Builds a DNS query message in the correct binary format.
	 * 
	 * @param hostname the domain name to resolve (e.g. "www.google.com")
	 * @return byte array representing the complete DNS query packet
	 * @throws Exception if an error occurs during query construction
	 */
	private static byte[] buildQuery(String hostname) throws Exception {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream out = new DataOutputStream(baos);

		// Generate random 16-bit identifier
		int id = new Random().nextInt(65536);

		// DNS HEADER
		out.writeShort(id & 0xFFFF);

		// Flags: RD = 1 (Recursion Desired)
		int flags = 0;
		flags |= (1 << 8);
		out.writeShort(flags);

		// Question count = 1
		out.writeShort(1);

		// No answers yet (query packet)
		out.writeShort(0);

		// No authority records
		out.writeShort(0);

		// No additional records
		out.writeShort(0);

		// QUESTION SECTION

		// Write domain name in DNS label format
		writeDomainName(out, hostname);

		// Query type = A record (IPv4)
		out.writeShort(TYPE_A);

		// Query class = Internet
		out.writeShort(CLASS_IN);

		out.flush();

		return baos.toByteArray();
	}

	/**
	 * Converts "www.example.com" into DNS label format: 3www7example3com0
	 * 
	 * @param out the output stream used to construct the DNS message
	 * @param domain the domain name to encode
	 * @throws Exception if a label exceeds the DNS maximum length (63 bytes)
	 */
	private static void writeDomainName(DataOutputStream out, String domain) throws Exception {

		String[] labels = domain.split("\\.");

		for (String label : labels) {

			byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);

			// DNS labels must be <= 63 bytes
			if (bytes.length > 63) {
				throw new IllegalArgumentException("Label too long: " + label);
			}

			// Write label length
			out.writeByte(bytes.length);

			// Write label characters
			out.write(bytes);
		}

		// End of domain name marker
		out.writeByte(0);
	}

	/**
	 * Parses the DNS response message and prints the sections.
	 * 
	 * @param msg byte array containing the raw DNS response message
	 * @throws Exception if the response format is invalid or parsing fails
	 */
	private static void parseAndPrintResponse(byte[] msg) throws Exception {
		int offset = 0;

		// HEADER
		int id = readUnsignedShort(msg, offset);
		offset += 2;
		int flags = readUnsignedShort(msg, offset);
		offset += 2;

		int qdCount = readUnsignedShort(msg, offset);
		offset += 2;
		int anCount = readUnsignedShort(msg, offset);
		offset += 2;
		int nsCount = readUnsignedShort(msg, offset);
		offset += 2;
		int arCount = readUnsignedShort(msg, offset);
		offset += 2;

		System.out.println(";; HEADER");
		System.out.println("ID: " + id);
		System.out.println("Questions: " + qdCount + " Answers: " + anCount + " Authority: " + nsCount + " Additional: "
				+ arCount);

		System.out.println();

		// QUESTION SECTION
		System.out.println(";; QUESTION SECTION:");

		for (int i = 0; i < qdCount; i++) {

			NameResult qname = readDomainName(msg, offset);
			offset = qname.nextOffset;

			int qtype = readUnsignedShort(msg, offset);
			offset += 2;
			int qclass = readUnsignedShort(msg, offset);
			offset += 2;

			System.out.println(qname.name + "\t" + classToString(qclass) + "\t" + typeToString(qtype));
		}

		System.out.println();

		// ANSWER SECTION
		System.out.println(";; ANSWER SECTION:");

		for (int i = 0; i < anCount; i++) {
			RRResult rr = readResourceRecord(msg, offset);
			offset = rr.nextOffset;
			System.out.println(rr.text);
		}

		System.out.println();

		// AUTHORITY SECTION
		System.out.println(";; AUTHORITY SECTION:");

		for (int i = 0; i < nsCount; i++) {
			RRResult rr = readResourceRecord(msg, offset);
			offset = rr.nextOffset;
			System.out.println(rr.text);
		}

		System.out.println();

		// ADDITIONAL SECTION
		System.out.println(";; ADDITIONAL SECTION:");
		for (int i = 0; i < arCount; i++) {
			RRResult rr = readResourceRecord(msg, offset);
			offset = rr.nextOffset;
			System.out.println(rr.text);
		}
	}

	/**
	 * Reads a resource record from the DNS message.
	 * 
	 * @param msg byte array containing the DNS message
	 * @param offset position within the message where the record begins
	 * @return RRResult object containing the formatted record text and
	 *         the offset of the next record in the message
	 * @throws Exception if parsing fails
	 */
	private static RRResult readResourceRecord(byte[] msg, int offset) throws Exception {
		NameResult nameResult = readDomainName(msg, offset);
		offset = nameResult.nextOffset;

		int type = readUnsignedShort(msg, offset);
		offset += 2;
		
		int rrClass = readUnsignedShort(msg, offset);
		offset += 2;

		long ttl = readUnsignedInt(msg, offset);
		offset += 4;

		int rdLength = readUnsignedShort(msg, offset);
		offset += 2;

		String rdataText;

		// If record contains IPv4 address
		if (type == TYPE_A && rdLength == 4) {
			rdataText = ipv4ToString(msg, offset);
		}
		// If record contains another domain name
		else if (type == TYPE_NS || type == TYPE_CNAME) {
			NameResult rname = readDomainName(msg, offset);
			rdataText = rname.name;

		} else {
			// Unknown type → print raw bytes
			rdataText = bytesToHex(msg, offset, rdLength);
		}

		String text = nameResult.name + "\t" + ttl + "\t" + classToString(rrClass) + "\t" + typeToString(type) + "\t"
				+ rdataText;

		return new RRResult(text, offset + rdLength);
	}

	/**
	 * Reads a domain name from the DNS message. Handles compression pointers.
	 * 
	 * @param msg byte array containing the DNS message
	 * @param offset position where the domain name begins
	 * @return NameResult containing the decoded name and the next offset
	 *         after the name field
	 * @throws Exception if the name format is invalid
	 */
	private static NameResult readDomainName(byte[] msg, int offset) throws Exception {

		StringBuilder name = new StringBuilder();

		int current = offset;
		int nextOffset = -1;
		boolean jumped = false;

		while (true) {

			int len = msg[current] & 0xFF;

			// Compression pointer
			if ((len & 0xC0) == 0xC0) {
				int b2 = msg[current + 1] & 0xFF;
				int pointer = ((len & 0x3F) << 8) | b2;

				if (!jumped) {
					nextOffset = current + 2;
				}

				current = pointer;
				jumped = true;
			}
			// End of domain name
			else if (len == 0) {
				if (!jumped) {
					nextOffset = current + 1;
				}
				break;
			} else {

				current++;

				if (name.length() > 0) {
					name.append(".");
				}

				for (int i = 0; i < len; i++) {
					name.append((char) (msg[current + i] & 0xFF));
				}
				
				current += len;
				
				if (!jumped) {
					nextOffset = current;
				}
			}
		}
		return new NameResult(name.toString(), nextOffset);
	}

	
	/**
	 * Reads a 16-bit unsigned integer from the DNS message.
	 *
	 * @param msg byte array containing the DNS message
	 * @param offset position of the 16-bit field
	 * @return unsigned integer value in the range 0–65535
	 */
	private static int readUnsignedShort(byte[] msg, int offset) {
		return ((msg[offset] & 0xFF) << 8) | (msg[offset + 1] & 0xFF);
	}

	/**
	 * Reads a 32-bit unsigned integer from the DNS message.
	 *
	 * @param msg byte array containing the DNS message
	 * @param offset position of the 32-bit field
	 * @return unsigned 32-bit value as a long
	 */
	private static long readUnsignedInt(byte[] msg, int offset) {
		return ((long) (msg[offset] & 0xFF) << 24) | ((long) (msg[offset + 1] & 0xFF) << 16)
				| ((long) (msg[offset + 2] & 0xFF) << 8) | ((long) (msg[offset + 3] & 0xFF));
	}

	
	/**
	 * Converts four bytes from the DNS message into a dotted IPv4 string.
	 *
	 * @param msg byte array containing the DNS message
	 * @param offset starting position of the IPv4 address
	 * @return human-readable IPv4 address string
	 */
	private static String ipv4ToString(byte[] msg, int offset) {
		return (msg[offset] & 0xFF) + "." + (msg[offset + 1] & 0xFF) + "." + (msg[offset + 2] & 0xFF) + "."
				+ (msg[offset + 3] & 0xFF);
	}

	/**
	 * Converts a sequence of bytes into a hexadecimal string.
	 *
	 * @param msg byte array containing the DNS message
	 * @param offset starting position of the byte sequence
	 * @param len number of bytes to convert
	 * @return hexadecimal string representation of the data
	 */
	private static String bytesToHex(byte[] msg, int offset, int len) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < len; i++) {
			sb.append(String.format("%02X", msg[offset + i]));
			if (i < len - 1) {
				sb.append(" ");
			}
		}
		return sb.toString();
	}

	/**
	 * Converts a DNS record type number into a readable string.
	 *
	 * @param type numeric DNS record type
	 * @return string representation of the type
	 */
	private static String typeToString(int type) {
		switch (type) {
		case TYPE_A:
			return "A";
		case TYPE_NS:
			return "NS";
		case TYPE_CNAME:
			return "CNAME";
		default:
			return "TYPE" + type;
		}
	}

	/**
	 * Converts a DNS class number into a readable string.
	 *
	 * @param rrClass numeric DNS class value
	 * @return string representation of the class
	 */
	private static String classToString(int rrClass) {
		if (rrClass == CLASS_IN)
			return "IN";

		return "CLASS" + rrClass;
	}

	// Helper structure for parsed domain names
	private static class NameResult {
		String name;
		int nextOffset;

		NameResult(String name, int nextOffset) {
			this.name = name;
			this.nextOffset = nextOffset;
		}
	}

	// Helper structure for parsed resource records
	private static class RRResult {
		String text;
		int nextOffset;

		RRResult(String text, int nextOffset) {
			this.text = text;
			this.nextOffset = nextOffset;
		}
	}
}