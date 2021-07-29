from sqlalchemy import Column, String, create_engine, Integer
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import transinfo_pb2_grpc
import transinfo_pb2
import logging
import grpc
import time
from concurrent import futures


def insert(dic, session):
    new_pkg = Pkg(dic)
    session.add(new_pkg)
    session.commit()


class TransInfo:

    def GetInfo(self, request, context):
        info_dic = eval(request.info)
        engine = create_engine(
            'mysql+mysqldb://root:password@localhost:3306/package')
        Base.metadata.create_all(engine)
        DBSession = sessionmaker(bind=engine)
        session = DBSession()
        insert(info_dic, session)
        session.close()
        print(request.info)
        return transinfo_pb2.SuccessReply(reply_code=len(request.info), reply="Hello client!")


Base = declarative_base()


class Pkg(Base):
    __tablename__ = 'pkg'

    id = Column(Integer, primary_key=True)
    Ty = Column(String(8))  # type
    protocol = Column(String(10))
    daddr = Column(String(40))
    dport = Column(Integer)
    saddr = Column(String(40))
    sport = Column(Integer)
    send_byte = Column(Integer)
    recv_byte = Column(Integer)
    pid = Column(Integer)
    time = Column(Integer)
    com = Column(String(20))

    def __init__(self, dic=None):
        # {'type': 'ip4', 'data': {'daddr': '192.168.200.200', 'send_byte': 1400, 'sport': '22', 'recv_byte': 1160, 'time': 1623748639.296404, 'dport': '6989', 'com': '7432', 'saddr': '30.0.1.77', 'pid': 7432}, 'protocol': 'tcp'}
        self.Ty = dic['type']
        self.protocol = dic['protocol']
        self.daddr = dic['data']['daddr']
        self.dport = int(dic['data']['dport'])
        self.saddr = dic['data']['saddr']
        self.sport = int(dic['data']['sport'])
        self.send_byte = int(dic['data']['send_byte'])
        self.recv_byte = int(dic['data']['recv_byte'])
        self.pid = dic['data']['pid']
        self.time = int(dic['data']['time'])
        self.com = dic['data']['com']


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    transinfo_pb2_grpc.add_TransInfoServicer_to_server(TransInfo(), server)
    server.add_insecure_port('[::]:11451')
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    logging.basicConfig()
    serve()


# # Query
# session = DBSession()
# pkg = session.query(Pkg).filter(Pkg.id == 1).one()  # .all()

# print('type:', type(pkg))
# print('time:', pkg.time)
# session.close()
