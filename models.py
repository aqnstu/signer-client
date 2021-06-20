# coding: utf-8
from sqlalchemy import Column, ForeignKey, Integer, TIMESTAMP, Table, Text, text
from sqlalchemy.sql.sqltypes import NullType
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
metadata = Base.metadata


class Datatype(Base):
    __tablename__ = 'datatype'

    id = Column(Integer, primary_key=True)
    name = Column(Text)
    description = Column(Text)
    added = Column(TIMESTAMP, nullable=False, server_default=text("current_timestamp"))
    xsd = Column(Text)


t_sqlite_sequence = Table(
    'sqlite_sequence', metadata,
    Column('name', NullType),
    Column('seq', NullType)
)


class Jwt(Base):
    __tablename__ = 'jwt'

    id = Column(Integer, primary_key=True)
    id_jwt_epgu = Column(Integer)
    id_datatype = Column(ForeignKey('datatype.id'))
    data = Column(Text)
    was_viewed = Column(Integer, server_default=text("0"))
    added = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    viewed = Column(TIMESTAMP)
    was_jsonify = Column(Integer, server_default=text("0"))
    jsonified = Column(TIMESTAMP)
    was_docify = Column(Integer, server_default=text("0"))
    docified = Column(TIMESTAMP)
    was_identify = Column(Integer, server_default=text("0"))
    identified = Column(TIMESTAMP)
    user_guid = Column(Text)

    datatype = relationship('Datatype')


class JwtDoc(Base):
    __tablename__ = 'jwt_doc'

    id = Column(Integer, primary_key=True)
    id_jwt = Column(ForeignKey('jwt.id'))
    id_documenttype = Column(Integer)
    data_json = Column(Text)
    added = Column(TIMESTAMP, server_default=text("current_timestamp"))

    jwt = relationship('Jwt')


class JwtJob(Base):
    __tablename__ = 'jwt_job'

    id = Column(Integer, primary_key=True)
    name = Column(Text)
    id_jwt = Column(ForeignKey('jwt.id'))
    status = Column(Integer)
    query_dump = Column(Text)
    added = Column(TIMESTAMP, nullable=False, server_default=text("current_timestamp"))

    jwt = relationship('Jwt')


class JwtJson(Base):
    __tablename__ = 'jwt_json'

    id = Column(Integer, primary_key=True)
    id_jwt = Column(ForeignKey('jwt.id'))
    json = Column(Text)
    added = Column(TIMESTAMP, nullable=False, server_default=text("current_timestamp"))
    status = Column(Integer, server_default=text("1"))

    jwt = relationship('Jwt')
