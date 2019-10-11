'''
import sqlite3

Date = '2019-08-17'
Ip = '10.0.0.154'
Time = '13-05-00'
Count = 5
Regular = 1
Ports = '22, 8080, 443'
Mac = '22:22:22:22:22:22'

conn = sqlite3.connect('Test.db')

c = conn.cursor()

#c.execute('CREATE TABLE IF NOT EXISTS test(date TEXT, ip TEXT, time TEXT, count INT, regular INT, ports INT, mac TEXT)')
#c.execute('INSERT INTO test (date, ip, time, count, regular, ports, mac) VALUES (?,?,?,?,?,?,?)',(Date, Ip, Time, Count, Regular, Ports, Mac))
c.execute('SELECT * FROM test')
result = c.fetchall()
print(result[0][1])

conn.commit()
c.close()
conn.close()
'''
'''
import sqlite3

Date = '2019-08-17'
Ip = '10.0.0.154'
Time = '13-05-00'
Count = 5
Regular = 1
Ports = '22, 8080, 443'
Mac = '22:22:22:22:22:22'

conn = sqlite3.connect('Test.db')

c = conn.cursor()

#c.execute('CREATE TABLE IF NOT EXISTS test(date TEXT, ip TEXT, time TEXT, count INT, regular INT, ports INT, mac TEXT)')
#c.execute('INSERT INTO test (date, ip, time, count, regular, ports, mac) VALUES (?,?,?,?,?,?,?)',(Date, Ip, Time, Count, Regular, Ports, Mac))
c.execute('SELECT * FROM test')
result = c.fetchall()
print(result[0][1])

conn.commit()
c.close()
conn.close()
'''

from tools import checkSQL

for x in range(100):
    ip = '10.0.0.' + str(x)
    mac = str(x) +':'+ str(x) +':'+ str(x) +':'+ str(x) +':'+ str(x) +':'+ str(x)
    checkSQL(x, ip, mac, 5, 1, '2019-08-17.15-50-00')