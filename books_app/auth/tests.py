import os
from unittest import TestCase

from datetime import date
 
from books_app import app, db, bcrypt
from books_app.models import Book, Author, Genre, User, Audience

"""
Run these tests with the command:
python -m unittest books_app.auth.tests
"""

#################################################
# Setup
#################################################

def create_books():
    a1 = Author(name='Harper Lee')
    b1 = Book(
        title='To Kill a Mockingbird',
        publish_date=date(1960, 7, 11),
        author=a1
    )
    db.session.add(b1)

    a2 = Author(name='Sylvia Plath')
    b2 = Book(title='The Bell Jar', author=a2)
    db.session.add(b2)
    db.session.commit()

def create_user():
    password_hash = bcrypt.generate_password_hash('password').decode('utf-8')
    user = User(username='me1', password=password_hash)
    db.session.add(user)
    db.session.commit()

#################################################
# Tests
#################################################

class AuthTests(TestCase):
    """Tests for authentication (login & signup)."""
 
    def setUp(self):
        """Executed prior to each test."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        db.drop_all()
        db.create_all()


    def test_signup(self):
        """Test signup route."""
        post_data = {
            'username': 'test',
            'password': 'test123'
        }
        self.app.post('/signup', data = post_data)

        new_user = User.query.filter_by(username = 'test')
        self.assertIsNotNone(new_user)


    def test_signup_existing_user(self):
        """Test to see if user already exists."""
        post_data = {
            'username': 'test',
            'password': 'test123'
        }
        self.app.post('/signup', data = post_data)

        response = self.app.post('/signup', data=post_data)
        response_text = response.get_data(as_text=True)
        self.assertIn('That username is taken. Please choose a different one.', response_text)


    def test_login_correct_password(self):
        """Test with correct login passowrd."""
        create_user()

        post_data = {
            'username': 'me1',
            'password': 'password'
        }
        self.app.post('/login', data = post_data)

        response = self.app.get('/', follow_redirects = True)
        response_text = response.get_data(as_text = True)
        self.assertIn('You are logged in as me1', response_text)


    def test_login_nonexistent_user(self):
        """Test with a non-existent user"""
        post_data = {
            'username': 'notreal',
            'password': 'notreal2'
        }
        response = self.app.post('/login', data = post_data)
       
        response_text = response.get_data(as_text=True)
        self.assertIn('No user with that username. Please try again.', response_text)


    def test_login_incorrect_password(self):
        """Test with incorrect password."""
        create_user()

        post_data = {
            'username': 'me1',
            'password': 'wrong'
        }
        response = self.app.post('/login', data = post_data)

        response_text = response.get_data(as_text=True)
        self.assertIn("Password doesn&#39;t match. Please try again.", response_text)
        

    def test_logout(self):
        """Test logout."""
        create_user()

        post_data = {
            'username': 'me1',
            'password': 'password'
        }
        response = self.app.post('/login', data = post_data)
        response = self.app.get('/logout', follow_redirects = True)

        response_text = response.get_data(as_text=True)
        self.assertNotIn('You are logged in as me1', response_text)
