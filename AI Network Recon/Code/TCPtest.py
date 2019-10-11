import socket

host = "192.168.17.166"
port = 80
c = 0
count = 0

while (count <= 100):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((host, port))
        s.shutdown(socket.SHUT_RD)
        c = 1
        count += 1

        if c:
            print("{}\t{}\t{} -- Established".format(host, port, count))
            c = 0

    except:
        print("No bueno")
