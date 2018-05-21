import os
import sys
from datetime import datetime, timedelta
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    password = Column(String(255), nullable=True)
    token = Column(String(255), nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'email': self.email,
        }

    @property
    def hash_password(self, password):
        self.password = pwd_context.encrypt(password)

    @property
    def verify_password(self, password):
        return pwd_context.verify(password, self.password)


class Catalog(Base):
    __tablename__ = 'catalogs'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    name = Column(String(255), nullable=False)
    description = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    user = relationship(User)
    #items = relationship(CatalogItem)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
            'author': self.user.name,
            'description': self.description,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }


class CatalogItem(Base):
    __tablename__ = 'catalog_items'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    catalog_id = Column(Integer, ForeignKey('catalogs.id'))
    name = Column(String(255), nullable=False)
    description = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    catalog = relationship(Catalog)
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'author': self.user.name,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }


engine = create_engine('postgres:///catalogdb')


Base.metadata.create_all(engine)