# Tools to manipulate the SQL database
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()

class Device(Base):
    __tablename__ = 'DEVICE'
    id = Column('ID', Integer, primary_key=True, unique=True)
    ip = Column('IP', String)
    mac = Column('MAC', String, unique=True)
    vnd = Column('VENDOR', String)
    cnt = Column('COUNT', Integer)
    reg = Column('REGULAR', Integer)
    dttm = Column('DATETIME', String)
    prt = Column('PORT', Integer)

engine = create_engine('sqlite:///Test.db', echo=False)
Base.metadata.create_all(bind=engine)
Session = sessionmaker(bind=engine)

# Create and make sure SQL Table is created
def checkSQL(ID, IPaddr, MACaddr, Vendor, Count, Regular, DateTime):
    session = Session()
    device = Device()
    device.id = ID
    device.ip = IPaddr
    device.mac = MACaddr
    device.vnd = Vendor
    device.cnt = Count
    device.reg = Regular
    device.dttm = DateTime
    session.add(device)
    session.commit()
    session.close()

# Primarily for ports an IP use, also adds IP, mac and vendor if not discovered by vendor
# In testing mode, changes will be made
def sqlPorty(Port, MACaddr):
    session = Session()
    test = session.query(Device).filter(Device.mac == MACaddr).one()
    print('TEST.PRT IS: {}'.format(test.prt))
    print('PORT IS: {}'.format(Port))
    wtf = test.prt
    if 'None' in str(test.prt):
        test.prt = Port
    if str(Port) in str(wtf):
        print('Skipping, same port')
    else:
        test.prt = str(Port) + ', ' + str(wtf)
    session.add(test)
    session.commit()
    session.close()

# Test to scan for blacklist ports
def sqlPortScan(Port, MACaddr):
    session = Session()
    sTst = session.query(Device).filter(Device.mac == MACaddr).one()
    portList = sTst.prt
    if Port in portList:
        print('!RED PORT FOUND!')
    else:
        print('No bad ports found...')