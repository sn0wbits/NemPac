import socket

host = '10.0.0.1'
ports = [22, 80, 8080]
c = 0
count = 0

for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        print('Checking:\t{}'.format(port))
        s.connect((host, port))
        s.shutdown(socket.SHUT_RD)
        c = 1
        count += 1

        if c:
            print('{}\t{}\t{} -- Established'.format(host, port, count))
            c = 0

    except:
        print('No bueno')
