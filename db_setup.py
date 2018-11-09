from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    '''
    User table class for sqlalchemy

    Attributes:
        id (Column): Integer id column
        name (Column): String name column
        email (Column): String email column
        picture (Column): String picture url column
    '''

    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

    @property
    def serialize(self):
        '''
        Serialization of attributes into dict used for json

        Returns:
            dict of attributes
        '''
        return {
            'name': self.name,
            'email': self.email,
            'picture': self.picture,
            'id': self.id,
        }


class Category(Base):
    '''
    Category table class for sqlalchemy

    Attributes:
        id (Column): Integer id column
        name (Column): String name column
    '''
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)

    @property
    def serialize(self):
        '''
        Serialization of attributes into dict used for json

        Returns:
            dict of attributes
        '''
        return {
            'id': self.id,
            'name': self.name,
        }


class Item(Base):
    '''
    Item table class for sqlalchemy

    Attributes:
        id (Column): Integer id column
        name (Column): String name column
        user_id (Column): String email column
        category_id (Column): String picture url column
        description (Column): String describig the item
    '''
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    category_id = Column(Integer, ForeignKey('category.id'))
    description = Column(String, nullable=False)

    @property
    def serialize(self):
        '''
        Serialization of attributes into dict used for json

        Returns:
            dict of attributes
        '''
        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.user_id,
            'category_id': self.category_id,
            'description': self.description,
        }


engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
