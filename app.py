from flask import Flask, render_template, request, redirect, url_for, flash, session,jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from model import predict_intrusion
from datetime import datetime, timedelta


# Initialize Flask app
app = Flask(__name__, template_folder="template")

# Configuration
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False




# Initialize SQLAlchemy
db = SQLAlchemy(app)

# User registration Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<User {self.email}>'
    
# This is the vehicle database model
class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Vehicle Details
    vin = db.Column(db.String(17), unique=True, nullable=False)
    license_plate = db.Column(db.String(20), unique=True, nullable=False)
    model = db.Column(db.String(100), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    vehicle_type = db.Column(db.String(50), nullable=False)
    
    # Owner Details
    owner_name = db.Column(db.String(100), nullable=False)
    contact_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    address = db.Column(db.Text, nullable=False)
    
    # Technical Details
    can_id = db.Column(db.String(50), nullable=False)
    mac_address = db.Column(db.String(17), nullable=False)
    device_id = db.Column(db.String(50), nullable=False)
    software_version = db.Column(db.String(20), nullable=False)
    
    # Registration timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Attack Detection Model
class AttackDetection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vehicle_model = db.Column(db.String(100), nullable=False)
    device_id = db.Column(db.String(50), nullable=False)
    can_id = db.Column(db.String(50), nullable=False)
    attack_type = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default="Attack")
    detected_at = db.Column(db.DateTime, default=datetime.now)



# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# routes
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('checkbox1') else False

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.', 'error')
            return redirect(url_for('index'))

        session['user_id'] = user.id
        session['user_name'] = user.name
        session['last_login'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if remember:
            session.permanent = True
        
        if remember:
            session.permanent = True

        flash('Logged in successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('index.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists', 'error')
            return redirect(url_for('register'))

        new_user = User(
            name=name,
            email=email,
            password=generate_password_hash(password)
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash('An error occurred during registration. Please try again.', 'error')
            return redirect(url_for('register'))

    return render_template('registration.html')



@app.route('/dashboard')
@login_required
def dashboard():
    # Get count of vehicles
    vehicle_count = Vehicle.query.count()
    
    # Get total attack count
    attack_count = AttackDetection.query.count()
    
    # Get latest attack detection
    latest_attack = AttackDetection.query.order_by(AttackDetection.detected_at.desc()).first()
    
    # Get latest vehicle registration
    latest_registration = Vehicle.query.order_by(Vehicle.created_at.desc()).first()
    
    # Get recent system activity (e.g., last login)
    recent_login = None
    if 'last_login' in session:
        recent_login = session['last_login']
    
    # Calculate time differences
    now = datetime.now()
    attack_time = None
    registration_time = None
    login_time = None
    
    if latest_attack:
        time_diff = now - latest_attack.detected_at
        if time_diff.days > 0:
            attack_time = f"{time_diff.days} days ago"
        elif time_diff.seconds // 3600 > 0:
            attack_time = f"{time_diff.seconds // 3600} hours ago"
        else:
            attack_time = f"{time_diff.seconds // 60} mins ago"
    
    if latest_registration:
        time_diff = now - latest_registration.created_at
        if time_diff.days > 0:
            registration_time = f"{time_diff.days} days ago"
        elif time_diff.seconds // 3600 > 0:
            registration_time = f"{time_diff.seconds // 3600} hours ago"
        else:
            registration_time = f"{time_diff.seconds // 60} mins ago"
    
    if recent_login:
        time_diff = now - datetime.strptime(recent_login, '%Y-%m-%d %H:%M:%S')
        if time_diff.days > 0:
            login_time = f"{time_diff.days} days ago"
        elif time_diff.seconds // 3600 > 0:
            login_time = f"{time_diff.seconds // 3600} hours ago"
        else:
            login_time = f"{time_diff.seconds // 60} mins ago"

    # Get monthly attack counts for security score
    current_year = datetime.now().year
    monthly_attacks = []
    month_labels = []
    return render_template(
        'dashboard.html', 
        name=session.get('user_name'),
        vehicle_count=vehicle_count,
        attack_count=attack_count,
        security_labels=month_labels,
        security_data=monthly_attacks,
        latest_attack=latest_attack,
        attack_time=attack_time,
        latest_registration=latest_registration,
        registration_time=registration_time,
        login_time=login_time
    )

#vehicle registration route
@app.route('/vehicle-registration', methods=['GET', 'POST'])
@login_required
def vehicle_registration():
    if request.method == 'POST':
        try:
            # Validate required fields
            required_fields = ['vin', 'license_plate', 'model', 'year', 'vehicle_type', 
                             'owner_name', 'contact_number', 'email', 'address', 
                             'can_id', 'mac_address', 'device_id', 'software_version']
            
            for field in required_fields:
                if not request.form.get(field):
                    flash(f'{field.replace("_", " ").title()} is required', 'error')
                    return redirect(url_for('vehicle_registration'))

            # Check if VIN or license plate already exists
            if Vehicle.query.filter_by(vin=request.form.get('vin')).first():
                flash('A vehicle with this VIN already exists', 'error')
                return redirect(url_for('vehicle_registration'))

            if Vehicle.query.filter_by(license_plate=request.form.get('license_plate')).first():
                flash('A vehicle with this license plate already exists', 'error')
                return redirect(url_for('vehicle_registration'))

            new_vehicle = Vehicle(
                vin=request.form.get('vin'),
                license_plate=request.form.get('license_plate'),
                model=request.form.get('model'),
                year=int(request.form.get('year')),
                vehicle_type=request.form.get('vehicle_type'),
                owner_name=request.form.get('owner_name'),
                contact_number=request.form.get('contact_number'),
                email=request.form.get('email'),
                address=request.form.get('address'),
                can_id=request.form.get('can_id'),
                mac_address=request.form.get('mac_address'),
                device_id=request.form.get('device_id'),
                software_version=request.form.get('software_version')
            )
            db.session.add(new_vehicle)
            db.session.commit()
            flash('Vehicle registration successful! The vehicle has been added to the system.', 'success')
            return redirect(url_for('vehicle_registration'))
            
        except ValueError:
            flash('Please enter valid data for all fields', 'error')
            return redirect(url_for('vehicle_registration'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error registering vehicle: {str(e)}', 'error')
            return redirect(url_for('vehicle_registration'))
    
    # Get all vehicles for display in table
    vehicles = Vehicle.query.all()
    return render_template('vehicle_registration.html', name=session.get('user_name'), vehicles=vehicles)



# Add new routes for delete and edit functionality
@app.route('/delete-vehicle/<int:vehicle_id>', methods=['DELETE'])
@login_required
def delete_vehicle(vehicle_id):
    try:
        vehicle = Vehicle.query.get_or_404(vehicle_id)
        db.session.delete(vehicle)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


# Edit Vehicle route
@app.route('/edit-vehicle/<int:vehicle_id>', methods=['GET', 'POST'])
@login_required
def edit_vehicle(vehicle_id):
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    
    if request.method == 'POST':
        try:
            # Validate required fields
            required_fields = ['vin', 'license_plate', 'model', 'year', 'vehicle_type', 
                             'owner_name', 'contact_number', 'email', 'address', 
                             'can_id', 'mac_address', 'device_id', 'software_version']
            
            for field in required_fields:
                if not request.form.get(field):
                    flash(f'{field.replace("_", " ").title()} is required', 'error')
                    return redirect(url_for('edit_vehicle', vehicle_id=vehicle_id))

            # Check if VIN or license plate exists and belongs to a different vehicle
            vin_check = Vehicle.query.filter_by(vin=request.form.get('vin')).first()
            if vin_check and vin_check.id != vehicle_id:
                flash('A vehicle with this VIN already exists', 'error')
                return redirect(url_for('edit_vehicle', vehicle_id=vehicle_id))

            plate_check = Vehicle.query.filter_by(license_plate=request.form.get('license_plate')).first()
            if plate_check and plate_check.id != vehicle_id:
                flash('A vehicle with this license plate already exists', 'error')
                return redirect(url_for('edit_vehicle', vehicle_id=vehicle_id))

            # Update vehicle details
            vehicle.vin = request.form.get('vin')
            vehicle.license_plate = request.form.get('license_plate')
            vehicle.model = request.form.get('model')
            vehicle.year = int(request.form.get('year'))
            vehicle.vehicle_type = request.form.get('vehicle_type')
            vehicle.owner_name = request.form.get('owner_name')
            vehicle.contact_number = request.form.get('contact_number')
            vehicle.email = request.form.get('email')
            vehicle.address = request.form.get('address')
            vehicle.can_id = request.form.get('can_id')
            vehicle.mac_address = request.form.get('mac_address')
            vehicle.device_id = request.form.get('device_id')
            vehicle.software_version = request.form.get('software_version')

            db.session.commit()
            flash('Vehicle updated successfully!', 'success')
            return redirect(url_for('vehicle_registration'))

        except ValueError:
            flash('Please enter valid data for all fields', 'error')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating vehicle: {str(e)}', 'error')

    return render_template('edit_vehicle.html', name=session.get('user_name'), vehicle=vehicle)



# intrusion detection route
@app.route('/intrusion-detection')
@login_required
def intrusion_detection():
    # Fetch vehicles with their model and device ID
    vehicles = Vehicle.query.with_entities(
        Vehicle.model, Vehicle.device_id, Vehicle.can_id
    ).all()
    
    # Format for dropdown: model(device_id)
    vehicle_data = [
        {
            'display': f"{vehicle.model}({vehicle.device_id})",
            'device_id': vehicle.device_id,
            'can_id': vehicle.can_id
        }
        for vehicle in vehicles
    ]
    
    return render_template('intrusion_detection.html', 
                         name=session.get('user_name'), 
                         vehicle_data=vehicle_data)




# vehicle status  route
@app.route('/vehicle-status')
@login_required
def vehicle_status():
    attacks = AttackDetection.query.order_by(AttackDetection.detected_at.desc()).all()
    return render_template('vehicle_status.html', name=session.get('user_name'), attacks=attacks)




# delete attack vehicle route
@app.route('/delete-attack/<int:attack_id>', methods=['DELETE'])
@login_required
def delete_attack(attack_id):
    try:
        attack = AttackDetection.query.get_or_404(attack_id)
        db.session.delete(attack)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})






# analytics route
@app.route('/analytics')
@login_required
def analytics():
    # Get all attacks from database
    attacks = AttackDetection.query.all()
    
    # Calculate total attacks
    total_attacks = len(attacks)
    
    # Calculate most common attack type
    attack_types_count = {}
    for attack in attacks:
        attack_types_count[attack.attack_type] = attack_types_count.get(attack.attack_type, 0) + 1
    most_common_attack = max(attack_types_count.items(), key=lambda x: x[1])[0] if attack_types_count else "None"
    
    # Calculate most targeted vehicle model
    vehicle_models_count = {}
    for attack in attacks:
        vehicle_models_count[attack.vehicle_model] = vehicle_models_count.get(attack.vehicle_model, 0) + 1
    most_targeted_model = max(vehicle_models_count.items(), key=lambda x: x[1])[0] if vehicle_models_count else "None"
    
    # Calculate attack rate
    total_vehicles = Vehicle.query.count()
    attack_rate = round((total_attacks / total_vehicles * 100) if total_vehicles > 0 else 0, 1)
    
    # Get data for daily attack trend (last 7 days)
    today = datetime.now().date()
    days = [(today - timedelta(days=i)) for i in range(6, -1, -1)]
    day_names = [(today - timedelta(days=i)).strftime('%a') for i in range(6, -1, -1)]
    daily_attacks = []
    
    for day in days:
        count = AttackDetection.query.filter(
            db.func.date(AttackDetection.detected_at) == day
        ).count()
        daily_attacks.append(count)

    # Pass the data to your template
    return render_template(
        'analytics.html',
        name=session.get('user_name'),
        total_attacks=total_attacks,
        most_common_attack=most_common_attack,
        most_targeted_model=most_targeted_model,
        attack_rate=attack_rate,
        # Data for charts
        chart_data={
            'trend_labels': day_names,
            'trend_data': daily_attacks,
            'attack_types': list(attack_types_count.keys()),
            'attack_values': list(attack_types_count.values()),
            'vehicle_models': list(vehicle_models_count.keys()),
            'vehicle_counts': list(vehicle_models_count.values())
        }
    )


# setting route
# Update the existing settings route
@app.route('/settings')
@login_required
def settings():
    user = User.query.get(session['user_id'])
    return render_template('settings.html', name=session.get('user_name'), user=user)

@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('settings'))
    
    try:
        # Update user details
        user.name = request.form.get('name')
        email = request.form.get('email')
        
        # Check if email already exists for another user
        existing_user = User.query.filter_by(email=email).first()
        if existing_user and existing_user.id != user.id:
            flash('Email already in use', 'error')
            return redirect(url_for('settings'))
        
        user.email = email
        
        # Update password only if provided
        new_password = request.form.get('new_password')
        if new_password:
            current_password = request.form.get('current_password')
            if not check_password_hash(user.password, current_password):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('settings'))
            user.password = generate_password_hash(new_password)
         
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        session['user_name'] = user.name  # Update session name
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating profile: {str(e)}', 'error')
    
    return redirect(url_for('settings'))

@app.route('/update-theme', methods=['POST'])
@login_required
def update_theme():
    theme = request.form.get('theme', 'light')
    session['theme'] = theme
    return jsonify({'success': True, 'theme': theme})


#logout route
@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))


# Create all database tables
with app.app_context():
    db.create_all()

# This is the model's route
predict_intrusion(app, db, AttackDetection)

if __name__ == '__main__':
    app.run(debug=True)