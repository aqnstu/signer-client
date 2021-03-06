# coding: utf-8
from sqlalchemy import Column, ForeignKey, Integer, TIMESTAMP, Table, Text, text
from sqlalchemy.sql.sqltypes import NullType
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
metadata = Base.metadata


class ApplicationList(Base):
    __tablename__ = 'application_list'

    id = Column(Integer, primary_key=True)
    uid_competitive_group = Column(Integer, nullable=False)
    name = Column(Text, nullable=False)
    base64file = Column(Text, nullable=False)
    fk_competition = Column(Integer, nullable=False)
    added = Column(TIMESTAMP, nullable=False, server_default=text("current_timestamp"))
    id_jwt_message = Column(Integer)
    was_viewed = Column(Integer, server_default=text("0"))
    message = Column(Text)
    viewed = Column(TIMESTAMP)


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


t_vw_jwt_achievement_to_nstu = Table(
    'vw_jwt_achievement_to_nstu', metadata,
    Column('id', Integer),
    Column('id_jwt', Integer),
    Column('id_jwt_epgu', Integer),
    Column('id_category', Integer),
    Column('user_guid', Text),
    Column('appnumber', Integer),
    Column('data_json', Text),
    Column('was_uploaded', Integer),
    Column('uploaded', TIMESTAMP)
)


t_vw_jwt_doc_to_nstu = Table(
    'vw_jwt_doc_to_nstu', metadata,
    Column('id', Integer),
    Column('id_jwt', Integer),
    Column('id_jwt_epgu', Integer),
    Column('id_documenttype', Integer),
    Column('user_guid', Text),
    Column('appnumber', Integer),
    Column('data_json', Text),
    Column('was_uploaded', Integer),
    Column('uploaded', TIMESTAMP)
)


t_vw_jwt_to_nstu = Table(
    'vw_jwt_to_nstu', metadata,
    Column('id', Integer),
    Column('id_jwt_epgu', Integer),
    Column('id_datatype', Integer),
    Column('user_guid', Text),
    Column('appnumber', Integer),
    Column('json', Text),
    Column('was_uploaded', Integer),
    Column('uploaded', TIMESTAMP)
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
    epgu_status = Column(Integer, server_default=text("1"))
    current_status = Column(Integer, server_default=text("1"))
    was_uploaded = Column(Integer, server_default=text("0"))
    uploaded = Column(TIMESTAMP)
    status_changed = Column(TIMESTAMP)
    appnumber = Column(Integer)
    was_confirmed = Column(Integer, server_default=text("0"))
    confirmed = Column(TIMESTAMP)
    was_achievementified = Column(Integer, server_default=text("0"))
    achievementified = Column(TIMESTAMP)

    datatype = relationship('Datatype')


class JwtAchievement(Base):
    __tablename__ = 'jwt_achievement'

    id = Column(Integer, primary_key=True)
    id_jwt = Column(ForeignKey('jwt.id'))
    id_category = Column(Integer)
    data_json = Column(Text)
    added = Column(TIMESTAMP, server_default=text("current_timestamp"))
    was_uploaded = Column(Integer, server_default=text("0"))
    uploaded = Column(TIMESTAMP)

    jwt = relationship('Jwt')


class JwtDoc(Base):
    __tablename__ = 'jwt_doc'

    id = Column(Integer, primary_key=True)
    id_jwt = Column(ForeignKey('jwt.id'))
    id_documenttype = Column(Integer)
    data_json = Column(Text)
    added = Column(TIMESTAMP, server_default=text("current_timestamp"))
    was_uploaded = Column(Integer, server_default=text("0"))
    uploaded = Column(TIMESTAMP)

    jwt = relationship('Jwt')


class JwtJob(Base):
    __tablename__ = 'jwt_job'

    id = Column(Integer, primary_key=True)
    name = Column(Text)
    id_jwt = Column(ForeignKey('jwt.id'))
    status = Column(Integer)
    query_dump = Column(Text)
    added = Column(TIMESTAMP, nullable=False, server_default=text("current_timestamp"))
    comment = Column(Text)

    jwt = relationship('Jwt')


class JwtJson(Base):
    __tablename__ = 'jwt_json'

    id = Column(Integer, primary_key=True)
    id_jwt = Column(ForeignKey('jwt.id'))
    json = Column(Text)
    added = Column(TIMESTAMP, nullable=False, server_default=text("current_timestamp"))
    status = Column(Integer, server_default=text("1"))

    jwt = relationship('Jwt')
