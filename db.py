# coding: utf-8
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


engine = create_engine("sqlite:///ss.sqlite", echo=True)

Session = sessionmaker(bind=engine)
session = Session()
