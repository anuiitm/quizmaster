from flask import Flask, render_template, redirect, url_for, session, request, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField, SelectField, validators, SubmitField, TextAreaField
from model import db, User, Subject, Chapter, Quiz, Question, UserAnswer,QuizResult
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import DataRequired, Regexp
from datetime import datetime, timedelta, date
from functools import wraps
from sqlalchemy import func
from flask_login import current_user, LoginManager, login_user, logout_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz_master.db'
app.config['SECRET_KEY'] = 'hello_there'  
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) 
app.config['SESSION_PERMANENT'] = False



# Initialize the database
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/login' 

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) 




# Create tables and admin user
with app.app_context():
    db.create_all()
    admin = User.query.filter_by(username='admin@quizmaster.com').first()
    if not admin:
        admin = User(
            username='admin@quizmaster.com',
            password=generate_password_hash('admin123'),
            full_name='Admin',
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

class SubjectForm(FlaskForm):
    name = StringField('Subject Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Submit')

class ChapterForm(FlaskForm):
    name = StringField('Chapter Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Add Chapter')
# Registration Form Class
class RegistrationForm(FlaskForm):
    username = StringField('Email', [
        validators.DataRequired(),
        validators.Email(message='Invalid email address')
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=8, message='Password must be at least 8 characters')
    ])
    full_name = StringField('Full Name', [validators.DataRequired()])
    qualification = SelectField('Qualification', choices=[
        ('', 'Select Qualification'),
        ('high_school', 'High School'),
        ('bachelor', "Bachelor's Degree"),
        ('master', "Master's Degree"),
        ('phd', "PhD")
    ], validators=[validators.DataRequired()])
    dob = DateField('Date of Birth', format='%Y-%m-%d', validators=[validators.DataRequired()])
# Login form class
class LoginForm(FlaskForm):
    username = StringField('Email', [
        validators.DataRequired(),
        validators.Email(message='Invalid email address')
    ])
    password = PasswordField('Password', [
        validators.DataRequired()
    ])
class UserEditForm(FlaskForm):
    full_name = StringField('Full Name', validators=[validators.DataRequired()])
    qualification = SelectField('Qualification', choices=[...])
    dob = DateField('Date of Birth')
    submit = SubmitField('Save Changes')

class QuizForm(FlaskForm):
    chapter = SelectField('Chapter', coerce=int, validators=[DataRequired()])
    date_of_quiz = DateField('Date of Quiz', validators=[DataRequired()])
    time_duration = StringField('Time Duration', validators=[
        DataRequired(),
        Regexp(r'^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$', message='Invalid time format. Use HH:MM.')
    ])
    remarks = TextAreaField('Remarks')
    submit = SubmitField('Create Quiz')

class QuestionForm(FlaskForm):
    title = StringField('Question Title', validators=[DataRequired()])
    question_statement = TextAreaField('Question Statement', validators=[DataRequired()])
    option1 = StringField('Option 1')
    option2 = StringField('Option 2')
    option3 = StringField('Option 3')
    option4 = StringField('Option 4')
    correct_option = SelectField('Correct Option', choices=[('1', 'Option 1'), ('2', 'Option 2'), ('3', 'Option 3'), ('4', 'Option 4')], validators=[DataRequired()])
    submit = SubmitField('Add Question')
class EditQuizForm(FlaskForm):
    chapter = SelectField('Chapter', coerce=int, validators=[DataRequired()])
    date_of_quiz = DateField('Date of Quiz', validators=[DataRequired()])
    time_duration = StringField('Time Duration', validators=[
        DataRequired(),
        Regexp(r'^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$', message='Invalid time format. Use HH:MM.')])
    submit = SubmitField('Update Quiz')









#admin authentication
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('You must be logged in as an admin to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# user authenitcation
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

#setting time for the session
@app.before_request
def before_request():
    session.permanent = True
    session.modified = True
    app.permanent_session_lifetime = timedelta(minutes=30)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))




@app.route('/')
def home():
    return render_template('home.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            session['user_id'] = user.id 
            session['is_admin'] = user.is_admin
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))  
            else:
                return redirect(url_for('user_dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('auth/login.html', form=form)




# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            password=generate_password_hash(form.password.data),
            full_name=form.full_name.data,
            qualification=form.qualification.data,
            dob=form.dob.data
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html', form=form)

# Dummy dashboard routes for testing

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    subjects = Subject.query.all()

    for subject in subjects:
        for chapter in subject.chapters:
            # Count questions for each chapter
            chapter.question_count = db.session.query(func.count(Question.id)).\
                join(Quiz).\
                filter(Quiz.chapter_id == chapter.id).\
                scalar()

    return render_template('admin_dashboard.html', subjects=subjects)


@app.route('/admin/subjects/create', methods=['GET', 'POST'])
@admin_required
def create_subject():
    form = SubjectForm()
    if form.validate_on_submit():
        new_subject = Subject(name=form.name.data, description=form.description.data)
        db.session.add(new_subject)
        db.session.commit()
        flash('Subject created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_subject.html', form=form)


@app.route('/admin/subjects/edit/<int:id>',methods=['GET','POST'])
@admin_required
def edit_subject(id):
    subject = Subject.query.get_or_404(id)
    form = SubjectForm(obj=subject)
    if form.validate_on_submit():
        subject.name = form.name.data
        subject.description = form.description.data
        db.session.commit()
        flash('Subject updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_subject.html', form=form, subject=subject)
@app.route('/admin/subjects/delete/<int:id>')
@admin_required
def delete_subject(id):
    subject = Subject.query.get_or_404(id)
    db.session.delete(subject)
    db.session.commit()
    flash('Subject deleted successfully!', 'success')
    return render_template('admin_dashboard.html')
@app.route('/admin/subjects/<int:subject_id>/add_chapter', methods=['GET', 'POST'])
@admin_required
def add_chapter(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    form = ChapterForm()
    if form.validate_on_submit():
        new_chapter = Chapter(name=form.name.data, description=form.description.data, subject_id=subject.id)
        db.session.add(new_chapter)
        db.session.commit()
        flash('Chapter added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('add_chapter.html', form=form, subject=subject)
@app.route('/admin/chapters/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_chapter(id):
    chapter = Chapter.query.get_or_404(id)
    form = ChapterForm(obj=chapter)
    if form.validate_on_submit():
        form.populate_obj(chapter)
        db.session.commit()
        flash('Chapter updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_chapter.html', form=form, chapter=chapter)
@app.route('/admin/chapters/delete/<int:id>')
@admin_required
def delete_chapter(id):
    chapter = Chapter.query.get_or_404(id)

    # Delete all quiz results before deleting quizzes
    quiz_ids = [quiz.id for quiz in chapter.quizzes]
    QuizResult.query.filter(QuizResult.quiz_id.in_(quiz_ids)).delete(synchronize_session=False)

    # Now delete quizzes
    Quiz.query.filter(Quiz.chapter_id == id).delete(synchronize_session=False)

    # Finally, delete the chapter
    db.session.delete(chapter)
    db.session.commit()

    flash('Chapter and associated quizzes deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/quizzes')
@admin_required
def quiz_page():
    quizzes = Quiz.query.all()
    return render_template('quiz_page.html', quizzes=quizzes)

@app.route('/admin/quizzes/create', methods=['GET', 'POST'])
@admin_required
def create_quiz():
    form = QuizForm()
    
    # Populate the chapter choices
    chapters = Chapter.query.all()
    form.chapter.choices = [(c.id, c.name) for c in chapters]
    
    if form.validate_on_submit():
        new_quiz = Quiz(
            chapter_id=form.chapter.data,
            date_of_quiz=form.date_of_quiz.data,
            time_duration=form.time_duration.data,
            remarks=form.remarks.data
        )
        db.session.add(new_quiz)
        db.session.commit()
        flash('Quiz created successfully!', 'success')
        return redirect(url_for('quiz_page'))
    return render_template('create_quiz.html', form=form)

@app.route('/admin/quizzes/<int:quiz_id>/add_question', methods=['GET', 'POST'])
@admin_required
def add_question(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    form = QuestionForm()
    
    if form.validate_on_submit():
        new_question = Question(
            quiz_id=quiz.id,
            title=form.title.data,
            question_statement=form.question_statement.data,
            option1=form.option1.data,
            option2=form.option2.data,
            option3=form.option3.data,
            option4=form.option4.data,
            correct_option=int(form.correct_option.data)
        )
        db.session.add(new_question)
        db.session.commit() 
        flash('Question added successfully!', 'success')
        return redirect(url_for('quiz_page'))
    
    return render_template('add_question.html', form=form, quiz=quiz)

@app.route('/admin/quizzes/edit/<int:quiz_id>', methods=['GET', 'POST'])
@admin_required
def edit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    form = EditQuizForm(obj=quiz)

    # Populate the chapter choices
    chapters = Chapter.query.all()
    form.chapter.choices = [(c.id, c.name) for c in chapters]

    if form.validate_on_submit():
        quiz.chapter_id = form.chapter.data
        quiz.date_of_quiz = form.date_of_quiz.data
        quiz.time_duration = form.time_duration.data
        db.session.commit()
        flash('Quiz updated successfully!', 'success')
        return redirect(url_for('quiz_page'))

    return render_template('edit_quiz.html', form=form, quiz=quiz)

@app.route('/admin/quizzes/delete_quiz/<int:quiz_id>') 
@admin_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    db.session.delete(quiz)
    db.session.commit()
    flash('Quiz deleted successfully', 'success')
    return redirect(url_for('quiz_page'))

@app.route('/admin/questions/edit/<int:question_id>', methods=['GET', 'POST'])
@admin_required
def edit_question(question_id):
    question = Question.query.get_or_404(question_id)
    form = QuestionForm(obj=question)
    
    if form.validate_on_submit():
        question.title = form.title.data
        question.question_statement = form.question_statement.data
        question.option1 = form.option1.data
        question.option2 = form.option2.data
        question.option3 = form.option3.data
        question.option4 = form.option4.data
        question.correct_option = int(form.correct_option.data)
        
        db.session.commit()
        flash('Question updated successfully!', 'success')
        return redirect(url_for('quiz_page'))
    
    return render_template('edit_question.html', form=form, question=question)



@app.route('/admin/questions/delete/<int:question_id>')
@admin_required
def delete_question(question_id):
    question = Question.query.get_or_404(question_id)
    db.session.delete(question)
    db.session.commit()
    flash('Question deleted successfully!', 'success')
    return redirect(url_for('quiz_page'))
@app.route('/admin/summary')
@admin_required
def admin_summary():
    # Fetching subject-wise highest and lowest scores
    subject_scores = db.session.query(
        Subject.name,
        func.max(QuizResult.score).label("max_score"),
        func.min(QuizResult.score).label("min_score")
    ).join(Chapter, Chapter.subject_id == Subject.id)\
     .join(Quiz, Quiz.chapter_id == Chapter.id)\
     .join(QuizResult, QuizResult.quiz_id == Quiz.id)\
     .group_by(Subject.name)\
     .all()

    # Fetching subject-wise user attempts
    subject_attempts = db.session.query(
        Subject.name,
        func.count(QuizResult.id).label("attempts")
    ).join(Chapter, Chapter.subject_id == Subject.id)\
     .join(Quiz, Quiz.chapter_id == Chapter.id)\
     .join(QuizResult, QuizResult.quiz_id == Quiz.id)\
     .group_by(Subject.name)\
     .all()

    # Convert to dictionaries for easy JSON use
    bar_chart_data = {
        "subjects": [row[0] for row in subject_scores],
        "max_scores": [row[1] for row in subject_scores],
        "min_scores": [row[2] for row in subject_scores]
    }

    pie_chart_data = {
        "subjects": [row[0] for row in subject_attempts],
        "attempts": [row[1] for row in subject_attempts]
    }

    return render_template('admin_summary.html', bar_chart_data=bar_chart_data, pie_chart_data=pie_chart_data)
















@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        flash('Please use Admin dashboard only','info')
        return redirect(url_for('admin_dashboard'))
    all_quizzes = Quiz.query.all()
    taken_quiz_ids = {qr.quiz_id for qr in QuizResult.query.filter_by(user_id=current_user.id).all()}
    return render_template('user_dashboard.html', user=current_user, all_quizzes=all_quizzes, taken_quiz_ids=taken_quiz_ids)
@app.route('/quiz/<int:quiz_id>/start')
@login_required
def start_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    quiz_taken = QuizResult.query.filter_by(user_id=current_user.id, quiz_id=quiz.id).first()
    if quiz_taken:
        flash("You have already taken this quiz.", "info")
        return redirect(url_for('user_dashboard'))
    return render_template('take_quiz.html', quiz=quiz)
@app.route('/quiz/<int:quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    quiz_result = QuizResult(user_id=current_user.id, quiz_id=quiz.id, score=0)  
    db.session.add(quiz_result)
    db.session.commit()
    correct_answers = 0
    for question in quiz.questions:
        user_answer = request.form.get(f'q{question.id}')
        if user_answer:
            is_correct = (int(user_answer) == question.correct_option)
            user_answer_entry = UserAnswer(
                quiz_result_id=quiz_result.id, 
                question_id=question.id,
                user_answer=user_answer,
                is_correct=is_correct
            )
            db.session.add(user_answer_entry)
            if is_correct:
                correct_answers += 1
    quiz_result.score = correct_answers
    db.session.commit()
    flash("Quiz submitted successfully!", "success")
    return redirect(url_for('user_dashboard'))
@app.route('/user/scores')
@login_required
def user_scores():
    quiz_results = db.session.query(QuizResult, Quiz.id, Quiz.date_of_quiz, func.count(Question.id))\
                    .join(Quiz, Quiz.id == QuizResult.quiz_id)\
                    .join(Question, Question.quiz_id == Quiz.id)\
                    .filter(QuizResult.user_id == current_user.id)\
                    .group_by(QuizResult.id, Quiz.id, Quiz.date_of_quiz)\
                    .order_by(QuizResult.date_taken.asc()).all()  # Oldest first
    return render_template('scores.html', user=current_user, quiz_results=quiz_results)
@app.route('/user/summary')
@login_required
def user_summary():
    # Fetch subject-wise number of quizzes attempted
    subject_attempts = db.session.query(
        Subject.name, func.count(QuizResult.id).label("attempts")
    ).join(Chapter, Chapter.subject_id == Subject.id)\
     .join(Quiz, Quiz.chapter_id == Chapter.id)\
     .join(QuizResult, QuizResult.quiz_id == Quiz.id)\
     .filter(QuizResult.user_id == current_user.id)\
     .group_by(Subject.name)\
     .all()

    # Fetch month-wise quiz attempts
    monthly_attempts = db.session.query(
        func.strftime('%m-%Y', QuizResult.date_taken).label("month"),
        func.count(QuizResult.id).label("attempts")
    ).filter(QuizResult.user_id == current_user.id)\
     .group_by("month")\
     .order_by("month")\
     .all()

    # Convert data into dictionary format
    bar_chart_data = {
        "subjects": [row[0] for row in subject_attempts],
        "attempt_counts": [row[1] for row in subject_attempts]
    }

    pie_chart_data = {
        "months": [row[0] for row in monthly_attempts],
        "attempts": [row[1] for row in monthly_attempts]
    }

    return render_template('user_summary.html', bar_chart_data=bar_chart_data, pie_chart_data=pie_chart_data)



















@app.route('/api/subjects', methods=['GET'])
def get_subjects():
    subjects = Subject.query.all()
    data = [{"id": s.id, "name": s.name, "description": s.description} for s in subjects]
    return jsonify(data)

@app.route('/api/subjects/<int:subject_id>/chapters', methods=['GET'])
def get_chapters(subject_id):
    chapters = Chapter.query.filter_by(subject_id=subject_id).all()
    data = [{"id": c.id, "name": c.name, "description": c.description} for c in chapters]
    return jsonify(data)

@app.route('/api/users/<int:user_id>/scores', methods=['GET'])
def get_scores(user_id):
    quiz_results = QuizResult.query.filter_by(user_id=user_id).all()
    data = [{"quiz_id": qr.quiz_id, "score": qr.score} for qr in quiz_results]
    return jsonify(data)

@app.route('/api/chapters/<int:chapter_id>/quizzes', methods=['GET'])
def get_quizzes(chapter_id):
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()
    data = [{"id": q.id, "date_of_quiz": q.date_of_quiz, "time_duration": q.time_duration} for q in quizzes]
    return jsonify(data)


















@app.route('/admin/search', methods=['POST'])
@admin_required
def admin_search():
    query = request.form.get('query', '').strip().lower()
    category = request.form.get('category', '').strip().lower()

    if not query:
        flash("Please enter a search term.", "danger")
        return redirect(url_for('admin_dashboard'))

    results = []

    if category == "quizzes":
        results = Quiz.query.join(Chapter).join(Subject).filter(
            (Quiz.id.ilike(f"%{query}%")) | 
            (Chapter.name.ilike(f"%{query}%")) | 
            (Subject.name.ilike(f"%{query}%"))
        ).all()
    elif category == "subjects":
        results = Subject.query.filter(Subject.name.ilike(f"%{query}%")).all()
    elif category == "users":
        results = User.query.filter(
            (User.full_name.ilike(f"%{query}%")) | 
            (User.username.ilike(f"%{query}%"))
        ).all()
    else:
        flash("Invalid category selected.", "danger")
        return redirect(url_for('admin_dashboard'))

    return render_template("admin_search_results.html", results=results, category=category)




@app.route('/user/search', methods=['POST'])
@login_required
def user_search_results():
    query = request.form.get('query', '').strip().lower()

    if not query:
        flash("Please enter a search term.", "danger")
        return redirect(url_for('user_dashboard'))

    # Check if the query matches a subject
    subjects = Subject.query.filter(Subject.name.ilike(f"%{query}%")).all()

    # If it's a subject, don't search for quizzes separately
    if subjects:
        quizzes = []
    else:
        # Otherwise, treat it as a quiz search
        quizzes = Quiz.query.join(Chapter).join(Subject).filter(
            (Quiz.id.ilike(f"%{query}%")) | 
            (Chapter.name.ilike(f"%{query}%")) | 
            (Subject.name.ilike(f"%{query}%"))
        ).all()

    # Fetch user's quiz results
    quiz_results = {qr.quiz_id: qr.score for qr in QuizResult.query.filter_by(user_id=current_user.id).all()}

    return render_template("user_search_results.html", quizzes=quizzes, subjects=subjects, quiz_results=quiz_results)



@app.route('/logout')
def logout():
    logout_user()
    session.clear()  # Clear all session data
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

