import socket

#host = '10.0.0.1'
hosts = []

for x in range(1, 254):
    hosts.append('10.0.0.' + str(x))

ports = [22, 80, 8080]
c = 0
count = 0

for host in hosts:
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            #print(f'Checking {host} - {port}')
            s.connect((host, port))
            s.shutdown(socket.SHUT_RD)
            c = 1
            count += 1
            if c:
                print(f'IP - {host}\tPORT - {port}\tCOUNT - {count} -- Established')
                #c = 0
                break
        except KeyboardInterrupt:
            print('Detected Keyboard Interrupt, exiting...')
            exit()
        except:
            #print('\tNo connection established...')
            pass
    if c:
        c = 0
        continue
