from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import select, func
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

# 1. Subject (no dependencies)
class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    chapters = db.relationship('Chapter', backref='subject', lazy=True)

# 2. Chapter (depends on Subject)
class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    quizzes = db.relationship('Quiz', backref='chapter', cascade='all,delete-orphan')

# 3. Quiz (depends on Chapter)
class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id',ondelete='CASCADE'), nullable=False)
    date_of_quiz = db.Column(db.Date)
    time_duration = db.Column(db.String(5))  # HH:MM format
    remarks = db.Column(db.Text)
    questions = db.relationship('Question', cascade='all, delete-orphan', backref='quiz', lazy='select')
    @hybrid_property
    def question_count(self):
        return len(self.questions)
    @question_count.expression
    def question_count(cls):
        return select([func.count(Question.id)]).where(Question.quiz_id == cls.id).label("question_count")

# 4. Question (depends on Quiz)
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id',ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    question_statement = db.Column(db.Text, nullable=False)
    option1 = db.Column(db.String(200))
    option2 = db.Column(db.String(200))
    option3 = db.Column(db.String(200))
    option4 = db.Column(db.String(200))
    correct_option = db.Column(db.Integer)

# 5. User 
class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(100))
    qualification = db.Column(db.String(100))
    dob = db.Column(db.Date, default=None)
    is_admin = db.Column(db.Boolean, default=False)
    scores = db.relationship('Score', backref='user', lazy=True)  # Use string 'Score'
    quizzes_taken = db.relationship('QuizResult', backref='user', lazy='dynamic')
    def __repr__(self):
        return f"<User {self.username}>"
# 6. Score
class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    time_stamp_of_attempt = db.Column(db.DateTime)
    total_scored = db.Column(db.Integer)

class UserAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_result_id = db.Column(db.Integer, db.ForeignKey('quiz_result.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    user_answer = db.Column(db.String(1))  # Assuming multiple choice answers A, B, C, D
    is_correct = db.Column(db.Boolean)
class QuizResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    score = db.Column(db.Integer)
    date_taken = db.Column(db.DateTime, default=datetime.utcnow)
    result = db.relationship('UserAnswer', backref='quiz_result', lazy='dynamic')
    quiz=db.relationship('Quiz', backref='results', lazy=True)
