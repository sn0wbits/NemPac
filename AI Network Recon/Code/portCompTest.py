from sqlTools import sqlPortScan

Ports = ['59180', '44438', '53090', '0000']

for p in Ports:
    sqlPortScan(p, 'cc:5d:4e:10:b6:cb')