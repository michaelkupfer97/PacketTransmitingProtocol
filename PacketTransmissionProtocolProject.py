import string


class Packet:
    """Represents a network packet.

    Attributes:
        source_address (str): The source IP address of the packet.
        destination_address (str): The destination IP address of the packet.
        sequence_number (int): The sequence number of the packet.
        is_ack (bool): Flag indicating whether the packet is an acknowledgment packet.
        data (str): The data contained in the packet.
    """

    def __init__(self, source_address, destination_address, sequence_number,
                 is_ack=False, data=None):
        self.__source_address = source_address
        self.__destination_address = destination_address
        self.__sequence_number = sequence_number
        self.__is_ack = is_ack
        self.__data = data

    def __repr__(self):
        """Return a string representation of the Packet."""
        str = "Packet(Source IP: {}, Dest IP: {}, #Seq: {}, Is ACK: {}, Data: {})".format(self.get_source_address(),
                                                                                          self.get_destination_address(),
                                                                                          self.get_sequence_number()
                                                                                          , self.get_is_ack()
                                                                                          , self.get_data())
        return str

    def get_source_address(self):
        """Get the source IP address of the packet.

        Returns:
            str: The source IP address.
        """
        return self.__source_address

    def get_destination_address(self):
        """Get the destination IP address of the packet.

        Returns:
            str: The destination IP address.
        """
        return self.__destination_address

    def get_sequence_number(self):
        """Get the sequence number of the packet.

        Returns:
            int: The sequence number.
        """
        return self.__sequence_number

    def set_sequence_number(self, seq_num):
        """Set the sequence number of the packet.

        Args:
            seq_num (int): The new sequence number.
        """
        self.__sequence_number = seq_num

    def get_is_ack(self):
        """Check if the packet is an acknowledgment packet.

        Returns:
            bool: True if the packet is an acknowledgment packet, False otherwise.
        """
        return self.__is_ack

    def get_data(self):
        """Get the data contained in the packet.

        Returns:
            str: The packet data.
        """
        return self.__data


class Communicator:
    """Represents a communication entity that sends and receives packets.

    Attributes:
        address (str): The address of the communicator.
        current_seq_num (int): The current sequence number for packet communication.
    """

    def __init__(self, address):
        self.__address = address
        self.__current_seq_num = None

    def get_address(self):
        """Get the address of the communicator.

        Returns:
            str: The address of the communicator.
        """
        return self.__address

    def get_current_sequence_number(self):
        """Get the current sequence number for packet communication.

        Returns:
            int: The current sequence number.
        """
        return self.__current_seq_num

    def set_current_sequence_number(self, seq_num):
        """Set the current sequence number for packet communication.

        Args:
            seq_num (int): The new sequence number.
        """
        self.__current_seq_num = seq_num

    def send_packet(self, packet):
        """Send a packet and print a message indicating the sequence number.

        Args:
            packet (Packet): The packet to be sent.
        """
        str = "Sender: Packet Seq Num: {} was sent".format(self.get_current_sequence_number())
        print(str)
        return packet

    def increment_current_seq_num(self):
        """Increment the current sequence number by 1."""
        self.set_current_sequence_number(self.get_current_sequence_number() + 1)


class Sender(Communicator):
    """Represents a sender communicating with other entities."""

    def __init__(self, address, num_letters_in_packet):
        """Initialize a Sender instance.

        Args:
            address (str): The address of the sender.
            num_letters_in_packet (int): The number of letters in each packet.
        """
        super().__init__(address)
        self.__num_letters_in_packet = num_letters_in_packet

    def prepare_packets(self, message, destination_address):
        """Prepare packets from a message to send to a destination address.

        Args:
            message (str): The message to be sent.
            destination_address (str): The address of the destination.

        Returns:
            list: A list of Packet objects.
        """
        if not message:
            # Handle case where message is empty
            return []

        if all(char in string.punctuation for char in message.strip()):
            # Handle case where message contains only special characters
            return "SpecialCharsOnly"



        packets_data = []
        packets = []
        """creating the list from the message."""
        for i in range(0, len(message), num_letters_in_packet):
            packet_data = message[i:i + num_letters_in_packet]
            packets_data.append(packet_data)
        """make sure that the last data has num_letters_in_packet chars."""
        if len(packets_data[-1]) < num_letters_in_packet:
            packets_data[-1] = packets_data[-1].ljust(num_letters_in_packet)
        """making the packets array, use packet initiator"""
        for i in range(len(packets_data)):
            packets.append(Packet(self.get_address(),
                                  destination_address,
                                  i,
                                  False,
                                  packets_data[i]))
        return packets

    def receive_ack(self, acknowledgment_packet):
        """Check if the acknowledgment packet is 'ACK'.

        Args:
            acknowledgment_packet (Packet): The acknowledgment packet.

        Returns:
            bool: True if the acknowledgment packet is 'ACK', False otherwise.
        """
        return acknowledgment_packet.get_is_ack()


class Receiver(Communicator):
    """Represents a receiver communicating with other entities."""

    def __init__(self, address):
        """Initialize a Receiver instance.

        Args:
            address (str): The address of the receiver.
        """
        super().__init__(address)
        self.received_packets = []

    def receive_packet(self, packet):
        """Receive a packet and send acknowledgment.

        Args:
            packet (Packet): The packet received.

        Returns:
            Packet: The acknowledgment packet.
        """
        self.received_packets.append(packet)
        Acknowledgment = Packet(packet.get_destination_address(),
                                packet.get_source_address(),
                                packet.get_sequence_number(),
                                True,
                                "ACK")
        print("Receiver: Received packet seq num: " + str(packet.get_sequence_number()))
        return Acknowledgment

    def get_message_by_received_packets(self):
        """Concatenate data from received packets to form a message.

        Returns:
            str: The concatenated message.
        """
        str = ''.join(packet.get_data() for packet in self.received_packets)
        return str


if __name__ == '__main__':
    source_address = "192.168.1.1"
    destination_address = "192.168.2.2"
    message = "!@#$% ^&^&*^&"
    num_letters_in_packet = 5

    sender = Sender(source_address, num_letters_in_packet)
    receiver = Receiver(destination_address)

    packets = sender.prepare_packets(message, receiver.get_address())

    if not packets:
        print("Not sending an empty string!")
        # Check if the message contains only special characters
    elif packets == "SpecialCharsOnly":
        print("Message contains only special characters")
    else:

        # setting current packet
        start_interval_index = packets[0].get_sequence_number()
        # setting current packet in the sender and receiver
        sender.set_current_sequence_number(start_interval_index)
        receiver.set_current_sequence_number(start_interval_index)

        # setting the last packet
        last_packet_sequence_num = packets[-1].get_sequence_number()
        receiver_current_packet = receiver.get_current_sequence_number()

        while receiver_current_packet <= last_packet_sequence_num:
            current_index = sender.get_current_sequence_number()
            packet = packets[current_index]
            packet = sender.send_packet(packet)

            ack = receiver.receive_packet(packet)

            result = sender.receive_ack(ack)

            if result == True:
                sender.increment_current_seq_num()
                receiver.increment_current_seq_num()

            receiver_current_packet = receiver.get_current_sequence_number()

        full_message = receiver.get_message_by_received_packets()
        print(f"Receiver message: {full_message}")
