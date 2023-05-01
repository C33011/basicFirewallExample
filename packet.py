
class Packet(object):

    #Acts as a sample packet
    def __init__(self,src,dst,port):
        self.src= src
        self.dst = dst
        self.port = port
        self.data = None


