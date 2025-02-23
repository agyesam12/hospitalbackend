# Hospital Backend System

## Overview
This project is a hospital management backend system built with Django. It supports user authentication, patient-doctor assignments, doctor note submissions, and dynamic scheduling of actionable steps based on live LLM processing.

## Features
- User authentication (JWT-based login/logout, admin control)
- Role-based access (Doctors, Patients, Admins, Workers)
- Doctor-patient assignments
- Secure encrypted doctor notes
- AI-driven actionable steps for treatment plans
- Task reminders and completion tracking
- Patient check-ins
- Django Admin panel for managing users and records
- Role-based access control decorators for views
- Unique ID generation for models
- Logging system for tracking user actions
- LLM processing for extracting actionable steps from doctor notes

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/agyesam12/hospitalbackend.git
   cd hospitalbackend
   ```
2. Create a virtual environment and activate it:
   ```bash
   python -m venv env
   source env/bin/activate  # On Windows use `env\\Scripts\\activate`
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run migrations:
   ```bash
   python manage.py migrate
   ```
5. Start the server:
   ```bash
   python manage.py runserver
   ```

## API Endpoints

### Authentication
- `POST /signup/` - User registration
- `POST /api_login/` - Obtain access & refresh tokens
- `POST /refresh/` - Refresh JWT token
- `POST /api_logout/` - Logout user

### Doctor-Patient Management
- `POST /assign/` - Assign a doctor to a patient
- `GET /my-doctors/` - Retrieve a patient's assigned doctors
- `GET /my-patients/` - Retrieve a doctor's patients

### Doctor Notes
- `POST /doctor-notes/submit/` - Submit an encrypted doctor note
- `GET /doctor-notes/retrieve/<patient_id>/` - Retrieve decrypted notes

### Actionable Steps
- `POST /checklist/complete/` - Mark checklist item as completed
- `POST /plan/complete/` - Mark a plan task as completed

### Reminders
- `GET /reminders/upcoming/` - Fetch upcoming reminders

## Models

### User
Handles authentication and stores user profile details, including:
- `full_name`, `email`, `phone_number`, `address`
- `role` (Doctor or Patient)
- `gender`, `date_of_birth`
- `photo`, `id_type`, `id_number`
- `is_doctor`, `is_patient`, `is_admin`, `is_worker`

### DoctorAssignment
Manages doctor-patient relationships:
- `patient` (ForeignKey to User)
- `doctor` (ForeignKey to User)
- `created_at` (Timestamp)

### DoctorNote
Stores encrypted notes from doctors:
- `doctor` (ForeignKey to User)
- `patient` (ForeignKey to User)
- `encrypted_notes` (TextField)
- `created_at` (Timestamp)

### ActionableStep
LLM-generated treatment steps:
- `note` (OneToOneField with DoctorNote)
- `checklist` (JSONField)
- `plan` (JSONField)
- `completed_checklist` (JSONField)
- `created_at` (Timestamp)

### Reminder
Schedules reminders for patients:
- `patient` (ForeignKey to User)
- `step` (ForeignKey to ActionableStep)
- `task_description` (TextField)
- `scheduled_at` (DateTimeField)
- `completed` (BooleanField)

### PatientCheckIn
Tracks patient progress:
- `patient` (ForeignKey to User)
- `timestamp` (DateTimeField)
- `completed_tasks` (JSONField)

### IntegerIDField (Custom ID Field)
Defines a unique 16-character alphanumeric ID for models:
- Uses `secrets` module for secure generation
- `unique`, `default=uniqueID`, `max_length=16`, `db_index=True`

### Logging System
Tracks user actions in the admin panel:
- Utilizes `LogEntry` from `django.contrib.admin.models`
- Records user actions including object changes
- `create_log_entry()` function facilitates logging

### LLM-Powered Actionable Steps
Extracts treatment plans from doctor notes using OpenAI:
- Uses GPT-4 or GPT-3.5-turbo to generate structured action items
- Converts unstructured notes into a checklist and plan
- Integrated directly into `ActionableStep` processing

## Serializers

### UserSignupSerializer
Handles user registration:
- Fields: `full_name`, `email`, `password`, `role`
- Hashes the password before saving

### DoctorAssignmentSerializer
Handles doctor-patient assignments:
- Fields: `id`, `patient`, `doctor`, `patient_name`, `doctor_name`, `created_at`

### DoctorNoteSerializer
Handles doctor notes:
- Fields: `id`, `doctor`, `patient`, `encrypted_notes`, `created_at`

### ActionableStepSerializer
Handles actionable steps:
- Fields: `id`, `note`, `checklist`, `completed_checklist`, `plan`, `created_at`
- Allows marking checklist items as completed

### ReminderSerializer
Handles patient reminders:
- Fields: `id`, `patient`, `step`, `task_description`, `scheduled_at`, `completed`

### PatientCheckInSerializer
Handles patient check-ins:
- Fields: `id`, `patient`, `timestamp`, `completed_tasks`
- Allows marking tasks as completed

## Admin Panel

The Django admin panel allows managing users and records efficiently. The following models are registered:
- `User`
- `LogEntry`
- `DoctorAssignment`
- `DoctorNote`
- `ActionableStep`
- `PatientCheckIn`
- `Reminder`

Access the admin panel at `/admin/` after creating a superuser.

## Role-Based Access Control (RBAC) Decorators

Custom decorators for role-based view access:
- `admin_required(view_func, denied_url="home")`
- `doctor_required(view_func, denied_url="home")`
- `patient_required(view_func, denied_url="home")`
- `closing_time(view_func, denied_url="closing_time")`

## Running Tests
To run the test suite, use:
```bash
python manage.py test
```

## Admin Access
To create a superuser:
```bash
python manage.py createsuperuser
```
Then log in at `/admin/`.

## Contributions
Contributions are welcome! Open a PR or issue for discussions.

## Dependencies
```
annotated-types==0.7.0
anyio==4.8.0
asgiref==3.8.1
certifi==2025.1.31
cffi==1.17.1
colorama==0.4.6
cryptography==44.0.1
distro==1.9.0
Django==5.1.6
djangorestframework==3.15.2
djangorestframework_simplejwt==5.4.0
h11==0.14.0
httpcore==1.0.7
httpx==0.28.1
idna==3.10
jiter==0.8.2
openai==1.63.0
pillow==11.1.0
pycparser==2.22
pydantic==2.10.6
pydantic_core==2.27.2
PyJWT==2.10.1
python-dotenv==1.0.1
sniffio==1.3.1
sqlparse==0.5.3
tqdm==4.67.1
typing_extensions==4.12.2
tzdata==2025.1
```
for any guidance contact +233544264029
whatsapp +233544264029



